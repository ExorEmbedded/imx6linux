/*
 *  GPIO driven matrix keyboard driver
 *
 *  Copyright (c) 2008 Marek Vasut <marek.vasut@gmail.com>
 *
 *  Based on corgikbd.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 */

#include <linux/types.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/input/matrix_keypad.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/kobject.h>

struct matrix_keypad {
	const struct matrix_keypad_platform_data *pdata;
	struct input_dev *input_dev;
	unsigned int row_shift;

	DECLARE_BITMAP(disabled_gpios, MATRIX_MAX_ROWS);

	uint32_t last_key_state[MATRIX_MAX_COLS];
	struct delayed_work work;
	spinlock_t lock;
	bool scan_pending;
	bool stopped;
	bool gpio_all_disabled;
	uint64_t raw_keymap;
};

static ssize_t key_read(struct file *filp, struct kobject *kobj,
						struct bin_attribute *bin_attr,
						char *buf, loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct platform_device *pdev = to_platform_device(dev);
	struct matrix_keypad *keypad = platform_get_drvdata(pdev);

	dev_dbg(&pdev->dev, "%s %llX  count: %ld offset %lld\n", __func__, keypad->raw_keymap, count, off);
	memcpy(buf, &keypad->raw_keymap, sizeof(keypad->raw_keymap));
	return count;
}

static struct bin_attribute key_attr = {
	.attr = {
		.name = "rawkeypad",
		.mode = S_IRUGO,
	},
	.size = sizeof(uint64_t),	//Size of matrix_keypad.raw_keymap var
	.read = key_read,
};



/*
 * NOTE: normally the GPIO has to be put into HiZ when de-activated to cause
 * minmal side effect when scanning other columns, here it is configured to
 * be input, and it should work on most platforms.
 */
static void __activate_col(const struct matrix_keypad_platform_data *pdata,
			   int col, bool on)
{
	bool level_on = pdata->col_active_high;

	if (on) {
		gpio_direction_output(pdata->col_gpios[col], level_on);
	} else {
		gpio_set_value_cansleep(pdata->col_gpios[col], !level_on);
		gpio_direction_input(pdata->col_gpios[col]);
	}
}

static void activate_col(const struct matrix_keypad_platform_data *pdata,
			 int col, bool on)
{
	__activate_col(pdata, col, on);

	if (on && pdata->col_scan_delay_ms)
		usleep_range(pdata->col_scan_delay_ms, pdata->col_scan_delay_ms+2000);
}

static void activate_all_cols(const struct matrix_keypad_platform_data *pdata,
			      bool on)
{
	int col;

	for (col = 0; col < pdata->num_col_gpios; col++)
		__activate_col(pdata, col, on);
}

static bool row_asserted(const struct matrix_keypad_platform_data *pdata,
			 int row)
{
	return gpio_get_value_cansleep(pdata->row_gpios[row]) ?
			!pdata->active_low : pdata->active_low;
}

static void enable_row_irqs(struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	int i;

	if (pdata->clustered_irq > 0)
		enable_irq(pdata->clustered_irq);
	else {
		for (i = 0; i < pdata->num_row_gpios; i++)
			enable_irq(gpio_to_irq(pdata->row_gpios[i]));
	}
}

static void disable_row_irqs(struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	int i;

	if (pdata->clustered_irq > 0)
		disable_irq_nosync(pdata->clustered_irq);
	else {
		for (i = 0; i < pdata->num_row_gpios; i++)
			disable_irq_nosync(gpio_to_irq(pdata->row_gpios[i]));
	}
}

/*
 * This gets the keys from keyboard and reports it to input subsystem
 */
static void matrix_keypad_scan(struct work_struct *work)
{
	struct matrix_keypad *keypad =
		container_of(work, struct matrix_keypad, work.work);
	struct input_dev *input_dev = keypad->input_dev;
	const unsigned short *keycodes = input_dev->keycode;
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	uint32_t new_state[MATRIX_MAX_COLS];
	int row, col, code;
	int npressed = 0;

	usleep_range(keypad->pdata->debounce_ms, keypad->pdata->debounce_ms+2000);

	/* de-activate all columns for scanning */
	activate_all_cols(pdata, false);

	memset(new_state, 0, sizeof(new_state));

	/* assert each column and read the row status out */
	for (col = 0; col < pdata->num_col_gpios; col++) {

		activate_col(pdata, col, true);

		for (row = 0; row < pdata->num_row_gpios; row++)
		{
			int tmp = row_asserted(pdata, row);
			new_state[col] |= tmp ? (1 << row) : 0;
			if (tmp) npressed++;
		}

		activate_col(pdata, col, false);
	}
	
	if(npressed > 2)
	{ /* Too many keys pressed ... reset the new status  */
		for (col = 0; col < pdata->num_col_gpios; col++)
			new_state[col] = 0;
	}

	for (col = 0; col < pdata->num_col_gpios; col++) {
		uint32_t bits_changed;

		bits_changed = keypad->last_key_state[col] ^ new_state[col];
		if (bits_changed == 0)
			continue;

		for (row = 0; row < pdata->num_row_gpios; row++) {
			if ((bits_changed & (1 << row)) == 0)
				continue;

			code = MATRIX_SCAN_CODE(row, col, keypad->row_shift);
			input_event(input_dev, EV_MSC, MSC_SCAN, code);
			input_report_key(input_dev,
					 keycodes[code],
					 new_state[col] & (1 << row));
			
			//printk("scancode=0x%x keycode=0x%x\n",code,keycodes[code]);

			if(new_state[col] & (1 << row))
				keypad->raw_keymap = keypad->raw_keymap | (1 << ((col*pdata->num_row_gpios)+row));
			else
				keypad->raw_keymap = keypad->raw_keymap & ~(1<<((col*pdata->num_row_gpios)+row));
		}
	}
#ifdef CONFIG_KEYBOARD_MATRIX_SHUTDOWN
	if((npressed==2) && (((pdata->shutdown_code1 != 0) || (pdata->shutdown_code2 != 0)) && (pdata->shutdown_count != 0)) )
	{
		uint32_t tmp = 0xffffffff;
		static uint16_t shutdown_counter = 0;
		for (col = 0; col < pdata->num_col_gpios; col++)
		{
			for (row = 0; row < pdata->num_row_gpios; row++)
				if( (new_state[col] & (1 << row)) != 0 )
				{
					code = MATRIX_SCAN_CODE(row, col, keypad->row_shift);
					tmp = (tmp << 16) | (code & 0xffff);
				}
		}
		if( (tmp & 0x0000FFFF) > ((tmp & 0xFFFF0000) >> 16) )
			tmp = ((tmp & 0x0000FFFF) << 16) | ((tmp & 0xFFFF0000) >> 16);

		if( ((pdata->shutdown_code1 != 0) && (pdata->shutdown_code1 == tmp)) ||
			((pdata->shutdown_code2 != 0) && (pdata->shutdown_code2 == tmp)) )
			shutdown_counter ++;
		else
			shutdown_counter = 0;

		if( shutdown_counter >= pdata->shutdown_count )
		{
			gpio_set_value_cansleep(pdata->enable_gpio, 0);
			msleep(1000);
			gpio_set_value_cansleep(pdata->enable_gpio, 1);
		}
		else
			gpio_set_value_cansleep(pdata->enable_gpio, 1);
	}
#endif
	input_sync(input_dev);

	memcpy(keypad->last_key_state, new_state, sizeof(new_state));

	activate_all_cols(pdata, true);

	/* Enable IRQs again */
	spin_lock_irq(&keypad->lock);
	keypad->scan_pending = false;
	enable_row_irqs(keypad);
	spin_unlock_irq(&keypad->lock);
}

static irqreturn_t matrix_keypad_interrupt(int irq, void *id)
{
	struct matrix_keypad *keypad = id;
	unsigned long flags;

	spin_lock_irqsave(&keypad->lock, flags);

	/*
	 * See if another IRQ beaten us to it and scheduled the
	 * scan already. In that case we should not try to
	 * disable IRQs again.
	 */
	if (unlikely(keypad->scan_pending || keypad->stopped))
		goto out;

	disable_row_irqs(keypad);
	keypad->scan_pending = true;
	schedule_delayed_work(&keypad->work, 0);

out:
	spin_unlock_irqrestore(&keypad->lock, flags);
	return IRQ_HANDLED;
}

static int matrix_keypad_start(struct input_dev *dev)
{
	struct matrix_keypad *keypad = input_get_drvdata(dev);

	keypad->stopped = false;
	mb();

	/*
	 * Schedule an immediate key scan to capture current key state;
	 * columns will be activated and IRQs be enabled after the scan.
	 */
	schedule_delayed_work(&keypad->work, 0);

	return 0;
}

static void matrix_keypad_stop(struct input_dev *dev)
{
	struct matrix_keypad *keypad = input_get_drvdata(dev);

	spin_lock_irq(&keypad->lock);
	keypad->stopped = true;
	spin_unlock_irq(&keypad->lock);

	flush_delayed_work(&keypad->work);
	/*
	 * matrix_keypad_scan() will leave IRQs enabled;
	 * we should disable them now.
	 */
	disable_row_irqs(keypad);
}

#ifdef CONFIG_PM_SLEEP
static void matrix_keypad_enable_wakeup(struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	unsigned int gpio;
	int i;

	if (pdata->clustered_irq > 0) {
		if (enable_irq_wake(pdata->clustered_irq) == 0)
			keypad->gpio_all_disabled = true;
	} else {

		for (i = 0; i < pdata->num_row_gpios; i++) {
			if (!test_bit(i, keypad->disabled_gpios)) {
				gpio = pdata->row_gpios[i];

				if (enable_irq_wake(gpio_to_irq(gpio)) == 0)
					__set_bit(i, keypad->disabled_gpios);
			}
		}
	}
}

static void matrix_keypad_disable_wakeup(struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	unsigned int gpio;
	int i;

	if (pdata->clustered_irq > 0) {
		if (keypad->gpio_all_disabled) {
			disable_irq_wake(pdata->clustered_irq);
			keypad->gpio_all_disabled = false;
		}
	} else {
		for (i = 0; i < pdata->num_row_gpios; i++) {
			if (test_and_clear_bit(i, keypad->disabled_gpios)) {
				gpio = pdata->row_gpios[i];
				disable_irq_wake(gpio_to_irq(gpio));
			}
		}
	}
}

static int matrix_keypad_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct matrix_keypad *keypad = platform_get_drvdata(pdev);

	matrix_keypad_stop(keypad->input_dev);

	if (device_may_wakeup(&pdev->dev))
		matrix_keypad_enable_wakeup(keypad);

	return 0;
}

static int matrix_keypad_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct matrix_keypad *keypad = platform_get_drvdata(pdev);

	if (device_may_wakeup(&pdev->dev))
		matrix_keypad_disable_wakeup(keypad);

	matrix_keypad_start(keypad->input_dev);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(matrix_keypad_pm_ops,
			 matrix_keypad_suspend, matrix_keypad_resume);

static int matrix_keypad_init_gpio(struct platform_device *pdev,
				   struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	int i, err;

	/* initialized strobe lines as outputs, activated */
	for (i = 0; i < pdata->num_col_gpios; i++) {
		err = gpio_request(pdata->col_gpios[i], "matrix_kbd_col");
		if (err) {
			dev_err(&pdev->dev,
				"failed to request GPIO%d for COL%d\n",
				pdata->col_gpios[i], i);
			goto err_free_cols;
		}

		gpio_direction_output(pdata->col_gpios[i], !pdata->active_low);
	}

	for (i = 0; i < pdata->num_row_gpios; i++) {
		err = gpio_request(pdata->row_gpios[i], "matrix_kbd_row");
		if (err) {
			dev_err(&pdev->dev,
				"failed to request GPIO%d for ROW%d\n",
				pdata->row_gpios[i], i);
			goto err_free_rows;
		}

		gpio_direction_input(pdata->row_gpios[i]);
	}

	if (pdata->clustered_irq > 0) {
		err = request_any_context_irq(pdata->clustered_irq,
				matrix_keypad_interrupt,
				pdata->clustered_irq_flags,
				"matrix-keypad", keypad);
		if (err < 0) {
			dev_err(&pdev->dev,
				"Unable to acquire clustered interrupt\n");
			goto err_free_rows;
		}
	} else {
		for (i = 0; i < pdata->num_row_gpios; i++) {
			err = request_any_context_irq(
					gpio_to_irq(pdata->row_gpios[i]),
					matrix_keypad_interrupt,
					IRQF_TRIGGER_RISING |
					IRQF_TRIGGER_FALLING,
					"matrix-keypad", keypad);
			if (err < 0) {
				dev_err(&pdev->dev,
					"Unable to acquire interrupt for GPIO line %i\n",
					pdata->row_gpios[i]);
				goto err_free_irqs;
			}
		}
	}

	/* initialized as disabled - enabled by input->open */
	disable_row_irqs(keypad);
	return 0;

err_free_irqs:
	while (--i >= 0)
		free_irq(gpio_to_irq(pdata->row_gpios[i]), keypad);
	i = pdata->num_row_gpios;
err_free_rows:
	while (--i >= 0)
		gpio_free(pdata->row_gpios[i]);
	i = pdata->num_col_gpios;
err_free_cols:
	while (--i >= 0)
		gpio_free(pdata->col_gpios[i]);

	return err;
}

static void matrix_keypad_free_gpio(struct matrix_keypad *keypad)
{
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	int i;

	if (pdata->clustered_irq > 0) {
		free_irq(pdata->clustered_irq, keypad);
	} else {
		for (i = 0; i < pdata->num_row_gpios; i++)
			free_irq(gpio_to_irq(pdata->row_gpios[i]), keypad);
	}

	for (i = 0; i < pdata->num_row_gpios; i++)
		gpio_free(pdata->row_gpios[i]);

	for (i = 0; i < pdata->num_col_gpios; i++)
		gpio_free(pdata->col_gpios[i]);
}

#ifdef CONFIG_OF
static struct matrix_keypad_platform_data *
matrix_keypad_parse_dt(struct device *dev)
{
	struct matrix_keypad_platform_data *pdata;
	struct device_node *np = dev->of_node;
	unsigned int *gpios;
	int ret, i, nrow, ncol;
	enum of_gpio_flags flags;
	uint32_t tmp __maybe_unused;

	if (!np) {
		dev_err(dev, "device lacks DT data\n");
		return ERR_PTR(-ENODEV);
	}

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata) {
		dev_err(dev, "could not allocate memory for platform data\n");
		return ERR_PTR(-ENOMEM);
	}

	pdata->num_row_gpios = nrow = of_gpio_named_count(np, "row-gpios");
	pdata->num_col_gpios = ncol = of_gpio_named_count(np, "col-gpios");
	if (nrow <= 0 || ncol <= 0) {
		dev_err(dev, "number of keypad rows/columns not specified\n");
		return ERR_PTR(-EINVAL);
	}

	if (of_get_property(np, "linux,no-autorepeat", NULL))
		pdata->no_autorepeat = true;

	if (of_get_property(np, "linux,wakeup", NULL))
		pdata->wakeup = true;

	if (of_get_property(np, "gpio-activelow", NULL))
		pdata->active_low = true;
	if (of_get_property(np, "gpio-colactivehigh", NULL))
		pdata->col_active_high = true;
	of_property_read_u32(np, "debounce-delay-ms", &pdata->debounce_ms);
	of_property_read_u32(np, "col-scan-delay-ms",
						&pdata->col_scan_delay_ms);
	pdata->debounce_ms*=1000;
	pdata->col_scan_delay_ms*=1000;

#ifdef CONFIG_KEYBOARD_MATRIX_SHUTDOWN
	pdata->shutdown_code1 = 0;
	pdata->shutdown_code2 = 0;

	//Get the 1st shutdown scancode pair and adjust it to have the lower value in the 16LSb
	if( !of_property_read_u32(np, "shutdown-code1", &tmp) )
	{
		if( (tmp & 0x0000FFFF) > ((tmp & 0xFFFF0000) >> 16) )
			tmp = ((tmp & 0x0000FFFF) << 16) | ((tmp & 0xFFFF0000) >> 16);

		pdata->shutdown_code1 = tmp;
	}

	//Get the 2nd shutdown scancode pair and adjust it to have the lower value in the 16LSb
	if( !of_property_read_u32(np, "shutdown-code2", &tmp) )
	{
		if( (tmp & 0x0000FFFF) > ((tmp & 0xFFFF0000) >> 16) )
			tmp = ((tmp & 0x0000FFFF) << 16) | ((tmp & 0xFFFF0000) >> 16);

		pdata->shutdown_code2 = tmp;
	}

	if( of_property_read_u32(np, "shutdown-count", &pdata->shutdown_count ) )
		pdata->shutdown_count    = 0;
#endif
	gpios = devm_kzalloc(dev,
			     sizeof(unsigned int) *
				(pdata->num_row_gpios + pdata->num_col_gpios),
			     GFP_KERNEL);
	if (!gpios) {
		dev_err(dev, "could not allocate memory for gpios\n");
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < nrow; i++) {
		ret = of_get_named_gpio(np, "row-gpios", i);
		if (ret < 0)
			return ERR_PTR(ret);
		gpios[i] = ret;
	}

	for (i = 0; i < ncol; i++) {
		ret = of_get_named_gpio(np, "col-gpios", i);
		if (ret < 0)
			return ERR_PTR(ret);
		gpios[nrow + i] = ret;
	}

	pdata->row_gpios = gpios;
	pdata->col_gpios = &gpios[pdata->num_row_gpios];

	pdata->enable_gpio = of_get_named_gpio_flags(np, "engpio", 0,  &flags);
	if (pdata->enable_gpio == -EPROBE_DEFER)
	{
		return ERR_PTR(-EPROBE_DEFER);
	}

	if( (pdata->enable_gpio >= 0) && (gpio_is_valid(pdata->enable_gpio)) )
	{
		dev_info( dev, "Request GPIO (engpio) = %d \n", pdata->enable_gpio );
		if (gpio_request_one( pdata->enable_gpio, flags, "stbgpio") < 0)
		{
			dev_err( dev, "failed to request GPIO %d \n", pdata->enable_gpio);
			return ERR_PTR(-ENODEV);
		}
		gpio_set_value_cansleep(pdata->enable_gpio, 1);
	}

	return pdata;
}
#else
static inline struct matrix_keypad_platform_data *
matrix_keypad_parse_dt(struct device *dev)
{
	dev_err(dev, "no platform data defined\n");

	return ERR_PTR(-EINVAL);
}
#endif
static int matrix_keypad_getkeycode(struct input_dev *input_dev,
									struct input_keymap_entry *ke)
{
	unsigned int scancode;
	struct matrix_keypad *keypad = input_get_drvdata(input_dev);
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;
	const uint32_t row_shift = get_count_order(pdata->num_col_gpios);
	const unsigned short *keycodes = input_dev->keycode;
	uint16_t r, c;
	bool stop = false;

	if (input_scancode_to_scalar(ke, &scancode))
		return -EINVAL;

	for(r=0; r<pdata->num_row_gpios && !stop; r++)
	{
		for(c=0; c<pdata->num_col_gpios && !stop; c++)
		{
			if(MATRIX_SCAN_CODE(r, c, row_shift) == scancode)
			{
				ke->keycode = keycodes[MATRIX_SCAN_CODE(r, c, row_shift)];
				ke->len = sizeof(scancode);
				memcpy(&ke->scancode, &scancode, sizeof(scancode));
				ke->index = keycodes[MATRIX_SCAN_CODE(r, c, row_shift)];
				stop = true;
			}
		}
	}

	return 0;
}

static int matrix_keypad_setkeycode(struct input_dev *input_dev,
									const struct input_keymap_entry *ke,
									unsigned int *old_keycode)
{
	unsigned int scancode;
	struct matrix_keypad *keypad = input_get_drvdata(input_dev);
	struct matrix_keypad_platform_data *pdata = keypad->pdata;
	const uint32_t row_shift = get_count_order(pdata->num_col_gpios);
	unsigned short *keycodes = input_dev->keycode;
	uint16_t r = 0, c = 0;
	bool stop = false;

	if (input_scancode_to_scalar(ke, &scancode))
		return -EINVAL;

	for(r=0; r<pdata->num_row_gpios && !stop; r++)
	{
		for(c=0; c<pdata->num_col_gpios && !stop; c++)
		{
			if(MATRIX_SCAN_CODE(r, c, row_shift) == scancode)
			{
//				dev_info(&input_dev->dev, "Change ScanCode=0x%x KeyCode from 0x%X to 0x%X \n", \
//						 MATRIX_SCAN_CODE(r, c, row_shift), keycodes[MATRIX_SCAN_CODE(r, c, row_shift)], ke->keycode );

				*old_keycode = keycodes[MATRIX_SCAN_CODE(r, c, row_shift)];
				keycodes[MATRIX_SCAN_CODE(r, c, row_shift)] =  ke->keycode;
				__set_bit(ke->keycode, input_dev->keybit);
				stop = true;
			}
		}
	}

	if(!stop) // key not found
		return -EINVAL;

	__clear_bit(*old_keycode, input_dev->keybit);
	return 0;
}

static int matrix_keypad_probe(struct platform_device *pdev)
{
	const struct matrix_keypad_platform_data *pdata;
	struct matrix_keypad *keypad;
	struct input_dev *input_dev;
	int err;

	pdata = dev_get_platdata(&pdev->dev);
	if (!pdata) {
		pdata = matrix_keypad_parse_dt(&pdev->dev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	} else if (!pdata->keymap_data) {
		dev_err(&pdev->dev, "no keymap data defined\n");
		return -EINVAL;
	}

	keypad = kzalloc(sizeof(struct matrix_keypad), GFP_KERNEL);
	input_dev = input_allocate_device();
	if (!keypad || !input_dev) {
		err = -ENOMEM;
		goto err_free_mem;
	}

	keypad->input_dev = input_dev;
	keypad->pdata = pdata;
	keypad->row_shift = get_count_order(pdata->num_col_gpios);
	keypad->stopped = true;
	INIT_DELAYED_WORK(&keypad->work, matrix_keypad_scan);
	spin_lock_init(&keypad->lock);

	input_dev->name		= pdev->name;
	input_dev->id.bustype	= BUS_HOST;
	input_dev->dev.parent	= &pdev->dev;
	input_dev->open		= matrix_keypad_start;
	input_dev->close	= matrix_keypad_stop;
	input_dev->getkeycode	= matrix_keypad_getkeycode;
	input_dev->setkeycode	= matrix_keypad_setkeycode;

	err = matrix_keypad_build_keymap(pdata->keymap_data, NULL,
					 pdata->num_row_gpios,
					 pdata->num_col_gpios,
					 NULL, input_dev);
	if (err) {
		dev_err(&pdev->dev, "failed to build keymap\n");
		goto err_free_mem;
	}

	if (!pdata->no_autorepeat)
		__set_bit(EV_REP, input_dev->evbit);
	input_set_capability(input_dev, EV_MSC, MSC_SCAN);
	input_set_drvdata(input_dev, keypad);

	err = matrix_keypad_init_gpio(pdev, keypad);
	if (err)
		goto err_free_mem;

	err = input_register_device(keypad->input_dev);
	if (err)
		goto err_free_gpio;

	device_init_wakeup(&pdev->dev, pdata->wakeup);
	platform_set_drvdata(pdev, keypad);

	/* create the sysfs key file */
	return sysfs_create_bin_file(&pdev->dev.kobj, &key_attr);

err_free_gpio:
	matrix_keypad_free_gpio(keypad);
err_free_mem:
	input_free_device(input_dev);
	kfree(keypad);
	return err;
}

static int matrix_keypad_remove(struct platform_device *pdev)
{
	struct matrix_keypad *keypad = platform_get_drvdata(pdev);
	const struct matrix_keypad_platform_data *pdata = keypad->pdata;

	device_init_wakeup(&pdev->dev, 0);

	if( (pdata->enable_gpio >= 0) && (gpio_is_valid(pdata->enable_gpio)) )
	{
		gpio_set_value_cansleep(pdata->enable_gpio, 0);
		gpio_free(pdata->enable_gpio);
	}

	matrix_keypad_free_gpio(keypad);
	input_unregister_device(keypad->input_dev);
	kfree(keypad);
	sysfs_remove_bin_file(&pdev->dev.kobj, &key_attr);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id matrix_keypad_dt_match[] = {
	{ .compatible = "gpio-matrix-keypad" },
	{ }
};
MODULE_DEVICE_TABLE(of, matrix_keypad_dt_match);
#endif

static struct platform_driver matrix_keypad_driver = {
	.probe		= matrix_keypad_probe,
	.remove		= matrix_keypad_remove,
	.driver		= {
		.name	= "matrix-keypad",
		.pm	= &matrix_keypad_pm_ops,
		.of_match_table = of_match_ptr(matrix_keypad_dt_match),
	},
};
module_platform_driver(matrix_keypad_driver);

MODULE_AUTHOR("Marek Vasut <marek.vasut@gmail.com>");
MODULE_DESCRIPTION("GPIO Driven Matrix Keypad Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:matrix-keypad");
