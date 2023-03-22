/*
 *  ekm32.c - Linux plugins manager driver
 *
 *  Written by: Luca Bargigli, Exor S.p.a.
 *  Copyright (c) 2023 Exor S.p.a.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "linux/usb/ekm32.h"

//#define DEBUG_EKM32

#define EKM32_VENDOR_ID 0x0483
#define EKM32_PRODUCT_ID 0xA0CA

/* Get a minor range for your devices from the usb maintainer */
#define USB_EKM32_MINOR_BASE	192

/* our private defines. if this grows any larger, use your own .h file */
#define MAX_TRANSFER		(PAGE_SIZE - 512)
/* MAX_TRANSFER is chosen so that the VM is not stressed by
   allocations > PAGE_SIZE and the number of packets in a page
   is an integer 512 is the largest possible packet on EHCI */
#define WRITES_IN_FLIGHT	8
/* arbitrarily chosen */

#define PRINT_USB_INTERFACE_DESCRIPTOR( i )                         \
{                                                                   \
    printk("USB_INTERFACE_DESCRIPTOR:\n");                         \
    printk("-----------------------------\n");                     \
    printk("bLength: 0x%x\n", i.bLength);                          \
    printk("bDescriptorType: 0x%x\n", i.bDescriptorType);          \
    printk("bInterfaceNumber: 0x%x\n", i.bInterfaceNumber);        \
    printk("bAlternateSetting: 0x%x\n", i.bAlternateSetting);      \
    printk("bNumEndpoints: 0x%x\n", i.bNumEndpoints);              \
    printk("bInterfaceClass: 0x%x\n", i.bInterfaceClass);          \
    printk("bInterfaceSubClass: 0x%x\n", i.bInterfaceSubClass);    \
    printk("bInterfaceProtocol: 0x%x\n", i.bInterfaceProtocol);    \
    printk("iInterface: 0x%x\n", i.iInterface);                    \
    printk("\n");                                                  \
}
#define PRINT_USB_ENDPOINT_DESCRIPTOR( e )                          \
{                                                                   \
    printk("USB_ENDPOINT_DESCRIPTOR:\n");                          \
    printk("------------------------\n");                          \
    printk("bLength: 0x%x\n", e.bLength);                          \
    printk("bDescriptorType: 0x%x\n", e.bDescriptorType);          \
    printk("bEndPointAddress: 0x%x\n", e.bEndpointAddress);        \
    printk("bmAttributes: 0x%x\n", e.bmAttributes);                \
    printk("wMaxPacketSize: 0x%x\n", e.wMaxPacketSize);            \
    printk("bInterval: 0x%x\n", e.bInterval);                      \
    printk("\n");                                                  \
}

static struct usb_device_id ekm32_table[] = {
    { USB_DEVICE(EKM32_VENDOR_ID, EKM32_PRODUCT_ID) },
    {} /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, ekm32_table);

struct usb_ekm32 {
	struct usb_device	*udev;			/* the usb device for this device */
	struct usb_interface	*interface;		/* the interface for this device */
	struct semaphore	limit_sem;		/* limiting the number of writes in progress */
	struct usb_anchor	submitted;		/* in case we need to retract our submissions */
	struct urb		*bulk_in_urb;		/* the urb to read data with */
	unsigned char           *bulk_in_buffer;	/* the buffer to receive data */
	size_t			bulk_in_size;		/* the size of the receive buffer */
	size_t			bulk_in_filled;		/* number of bytes in the buffer */
	size_t			bulk_in_copied;		/* already copied to user space */
	__u8			bulk_in_endpointAddr;	/* the address of the bulk in endpoint */
	__u8			bulk_out_endpointAddr;	/* the address of the bulk out endpoint */
	int			errors;			/* the last request tanked */
	bool			ongoing_read;		/* a read is going on */
	spinlock_t		err_lock;		/* lock for errors */
	struct kref		kref;
	struct mutex		io_mutex;		/* synchronize I/O with disconnect */
	wait_queue_head_t	bulk_in_wait;		/* to wait for an ongoing read */
};
#define to_ekm32_dev(d) container_of(d, struct usb_ekm32, kref)


static struct usb_driver ekm32_driver;
static void ekm32_draw_down(struct usb_ekm32 *dev);

#ifdef DEBUG_EKM32
a
static void showarray(const char* buf,int size)
{
	int i;

	if (buf == NULL)
	{
		printk("empty buffer");
		return;
	}
	for (i = 0; i < size; i++)
	{
		if (i > 0) printk(":");
		printk("%02X", buf[i]);
	}
	printk("\n");
}
#endif

static void ekm32_delete(struct kref *kref)
{
	struct usb_ekm32 *dev = to_ekm32_dev(kref);
#ifdef DEBUG_EKM32
	printk("ekm32_delete"); // debug
#endif
	usb_free_urb(dev->bulk_in_urb);
	usb_put_dev(dev->udev);
	kfree(dev->bulk_in_buffer);
	kfree(dev);
}

static int ekm32_open(struct inode *inode, struct file *file)
{
	struct usb_ekm32 *dev;
	struct usb_interface *interface;
	int subminor;
	int retval = 0;
#ifdef DEBUG_EKM32
	printk("ekm32_open"); // debug
#endif
	subminor = iminor(inode);

	interface = usb_find_interface(&ekm32_driver, subminor);
	if (!interface) {
		pr_err("%s - error, can't find device for minor %d\n",
			__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}

	dev = usb_get_intfdata(interface);
	if (!dev) {
		retval = -ENODEV;
		goto exit;
	}

	retval = usb_autopm_get_interface(interface);
	if (retval)
		goto exit;

	/* increment our usage count for the device */
	kref_get(&dev->kref);

	/* save our object in the file's private structure */
	file->private_data = dev;

exit:
	return retval;
}

static int ekm32_release(struct inode *inode, struct file *file)
{
	struct usb_ekm32 *dev;
#ifdef DEBUG_EKM32
	printk("ekm32_release"); // debug
#endif
	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* allow the device to be autosuspended */
	mutex_lock(&dev->io_mutex);
	if (dev->interface)
		usb_autopm_put_interface(dev->interface);
	mutex_unlock(&dev->io_mutex);

	/* decrement the count on our device */
	kref_put(&dev->kref, ekm32_delete);
	return 0;
}

static int ekm32_flush(struct file *file, fl_owner_t id)
{
	struct usb_ekm32 *dev;
	int res;
#ifdef DEBUG_EKM32
	printk("ekm32_flush"); // debug
#endif
	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* wait for io to stop */
	mutex_lock(&dev->io_mutex);
	ekm32_draw_down(dev);

	/* read out errors, leave subsequent opens a clean slate */
	spin_lock_irq(&dev->err_lock);
	res = dev->errors ? (dev->errors == -EPIPE ? -EPIPE : -EIO) : 0;
	dev->errors = 0;
	spin_unlock_irq(&dev->err_lock);

	mutex_unlock(&dev->io_mutex);

	return res;
}

static void ekm32_read_bulk_callback(struct urb *urb)
{
	struct usb_ekm32 *dev;
#ifdef DEBUG_EKM32
	printk("ekm32_read_bulk"); // debug
#endif

	dev = urb->context;

	spin_lock(&dev->err_lock);
	/* sync/async unlink faults aren't errors */
	if (urb->status) {
		if (!(urb->status == -ENOENT ||
		    urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev,
				"%s - nonzero write bulk status received: %d\n",
				__func__, urb->status);

		dev->errors = urb->status;
	} else {
		dev->bulk_in_filled = urb->actual_length;
	}
	dev->ongoing_read = 0;
	spin_unlock(&dev->err_lock);

	wake_up_interruptible(&dev->bulk_in_wait);
}

static int ekm32_do_read_io(struct usb_ekm32 *dev, size_t count)
{
	int rv;
#ifdef DEBUG_EKM32
	printk("ekm32_read_io"); // debug
#endif

	/* prepare a read */
	usb_fill_bulk_urb(dev->bulk_in_urb,
			dev->udev,
			usb_rcvbulkpipe(dev->udev,
				dev->bulk_in_endpointAddr),
			dev->bulk_in_buffer,
			min(dev->bulk_in_size, count),
			ekm32_read_bulk_callback,
			dev);
	/* tell everybody to leave the URB alone */
	spin_lock_irq(&dev->err_lock);
	dev->ongoing_read = 1;
	spin_unlock_irq(&dev->err_lock);

	/* submit bulk in urb, which means no data to deliver */
	dev->bulk_in_filled = 0;
	dev->bulk_in_copied = 0;

	/* do it */
	rv = usb_submit_urb(dev->bulk_in_urb, GFP_KERNEL);
	if (rv < 0) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting read urb, error %d\n",
			__func__, rv);
		rv = (rv == -ENOMEM) ? rv : -EIO;
		spin_lock_irq(&dev->err_lock);
		dev->ongoing_read = 0;
		spin_unlock_irq(&dev->err_lock);
	}

	return rv;
}

static ssize_t ekm32_read(struct file *file, char *buffer, size_t count,
			 loff_t *ppos)
{
	struct usb_ekm32 *dev;
	int rv;
	bool ongoing_io;
#ifdef DEBUG_EKM32
	printk("ekm32_read"); // debug
#endif

	dev = file->private_data;

	/* if we cannot read at all, return EOF */
	if (!dev->bulk_in_urb || !count)
		return 0;

	/* no concurrent readers */
	rv = mutex_lock_interruptible(&dev->io_mutex);
	if (rv < 0)
		return rv;

	if (!dev->interface) {		/* disconnect() was called */
		rv = -ENODEV;
		goto exit;
	}

	/* if IO is under way, we must not touch things */
retry:
	spin_lock_irq(&dev->err_lock);
	ongoing_io = dev->ongoing_read;
	spin_unlock_irq(&dev->err_lock);

	if (ongoing_io) {
		/* nonblocking IO shall not wait */
		if (file->f_flags & O_NONBLOCK) {
			rv = -EAGAIN;
			goto exit;
		}
		/*
		 * IO may take forever
		 * hence wait in an interruptible state
		 */
		rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
		if (rv < 0)
			goto exit;
	}

	/* errors must be reported */
	rv = dev->errors;
	if (rv < 0) {
		/* any error is reported once */
		dev->errors = 0;
		/* to preserve notifications about reset */
		rv = (rv == -EPIPE) ? rv : -EIO;
		/* report it */
		goto exit;
	}

	/*
	 * if the buffer is filled we may satisfy the read
	 * else we need to start IO
	 */

	if (dev->bulk_in_filled) {
		/* we had read data */
		size_t available = dev->bulk_in_filled - dev->bulk_in_copied;
		size_t chunk = min(available, count);

		if (!available) {
			/*
			 * all data has been used
			 * actual IO needs to be done
			 */
			rv = ekm32_do_read_io(dev, count);
			if (rv < 0)
				goto exit;
			else
				goto retry;
		}
		/*
		 * data is available
		 * chunk tells us how much shall be copied
		 */

		if (copy_to_user(buffer,
				 dev->bulk_in_buffer + dev->bulk_in_copied,
				 chunk))
			rv = -EFAULT;
		else
			rv = chunk;

		dev->bulk_in_copied += chunk;

		/*
		 * if we are asked for more than we have,
		 * we start IO but don't wait
		 */
		if (available < count)
			ekm32_do_read_io(dev, count - chunk);
	} else {
		/* no data in the buffer */
		rv = ekm32_do_read_io(dev, count);
		if (rv < 0)
			goto exit;
		else
			goto retry;
	}
exit:
	mutex_unlock(&dev->io_mutex);
	return rv;
}

static void ekm32_write_bulk_callback(struct urb *urb)
{
	struct usb_ekm32 *dev;
#ifdef DEBUG_EKM32
	printk("ekm32_write_bulk"); // debug
#endif

	dev = urb->context;

	/* sync/async unlink faults aren't errors */
	if (urb->status) {
		if (!(urb->status == -ENOENT ||
		    urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev,
				"%s - nonzero write bulk status received: %d\n",
				__func__, urb->status);

		spin_lock(&dev->err_lock);
		dev->errors = urb->status;
		spin_unlock(&dev->err_lock);
	}

	/* free up our allocated buffer */
	usb_free_coherent(urb->dev, urb->transfer_buffer_length,
			  urb->transfer_buffer, urb->transfer_dma);
	up(&dev->limit_sem);
}

static ssize_t ekm32_write(struct file *file, const char *user_buffer,
			  size_t count, loff_t *ppos)
{
	struct usb_ekm32 *dev;
	int retval = 0;
	struct urb *urb = NULL;
	char *buf = NULL;
	size_t writesize = min(count, (size_t)MAX_TRANSFER);
#ifdef DEBUG_EKM32
	printk("ekm32_write"); // debug
	showarray(user_buffer,count); // debug
#endif

	dev = file->private_data;

	/* verify that we actually have some data to write */
	if (count == 0)
		goto exit;

	/*
	 * limit the number of URBs in flight to stop a user from using up all
	 * RAM
	 */
	if (!(file->f_flags & O_NONBLOCK)) {
		if (down_interruptible(&dev->limit_sem)) {
			retval = -ERESTARTSYS;
			goto exit;
		}
	} else {
		if (down_trylock(&dev->limit_sem)) {
			retval = -EAGAIN;
			goto exit;
		}
	}

	spin_lock_irq(&dev->err_lock);
	retval = dev->errors;
	if (retval < 0) {
		/* any error is reported once */
		dev->errors = 0;
		/* to preserve notifications about reset */
		retval = (retval == -EPIPE) ? retval : -EIO;
	}
	spin_unlock_irq(&dev->err_lock);
	if (retval < 0)
		goto error;

	/* create a urb, and a buffer for it, and copy the data to the urb */
	urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!urb) {
		retval = -ENOMEM;
		goto error;
	}

	buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
				 &urb->transfer_dma);
	if (!buf) {
		retval = -ENOMEM;
		goto error;
	}

	if (copy_from_user(buf, user_buffer, writesize)) {
		retval = -EFAULT;
		goto error;
	}

	/* this lock makes sure we don't submit URBs to gone devices */
	mutex_lock(&dev->io_mutex);
	if (!dev->interface) {		/* disconnect() was called */
		mutex_unlock(&dev->io_mutex);
		retval = -ENODEV;
		goto error;
	}

	/* initialize the urb properly */
	usb_fill_bulk_urb(urb, dev->udev,
			  usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
			  buf, writesize, ekm32_write_bulk_callback, dev);
	urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	usb_anchor_urb(urb, &dev->submitted);

	//printk("write to usb buffer"); // debug
	/* send the data out the bulk port */
	retval = usb_submit_urb(urb, GFP_KERNEL);
	mutex_unlock(&dev->io_mutex);
	if (retval) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		goto error_unanchor;
	}

	/*
	 * release our reference to this urb, the USB core will eventually free
	 * it entirely
	 */
	usb_free_urb(urb);


	return writesize;

error_unanchor:
	usb_unanchor_urb(urb);
error:
	if (urb) {
		usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
		usb_free_urb(urb);
	}
	up(&dev->limit_sem);

exit:
	return retval;
}

static const struct file_operations ekm32_fops = {
	.owner =	THIS_MODULE,
	.read =		ekm32_read,
	.write =	ekm32_write,
	.open =		ekm32_open,
	.release =	ekm32_release,
	.flush =	ekm32_flush,
	.llseek =	noop_llseek,
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
static struct usb_class_driver ekm32_class = {
	.name =		"ekm32%d",
	.fops =		&ekm32_fops,
	.minor_base =	USB_EKM32_MINOR_BASE,
};

static int ekm32_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_ekm32 *dev;
	struct usb_endpoint_descriptor *bulk_in, *bulk_out;
	int retval;
#ifdef DEBUG_EKM32
	unsigned int endpoints_count;
	unsigned int i;
	printk("ekm32_probe"); // debug
#endif	

	/* allocate memory for our device state and initialize it */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	kref_init(&dev->kref);
	sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
	mutex_init(&dev->io_mutex);
	spin_lock_init(&dev->err_lock);
	init_usb_anchor(&dev->submitted);
	init_waitqueue_head(&dev->bulk_in_wait);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;
#ifdef DEBUG_EKM32
	PRINT_USB_INTERFACE_DESCRIPTOR(interface->cur_altsetting->desc);
	endpoints_count = interface->cur_altsetting->desc.bNumEndpoints;
	for ( i = 0; i < endpoints_count; i++ ) {
          PRINT_USB_ENDPOINT_DESCRIPTOR(interface->cur_altsetting->endpoint[i].desc);
     }
#endif	

	/* set up the endpoint information */
	/* use only the first bulk-in and bulk-out endpoints */
	retval = usb_find_common_endpoints(interface->cur_altsetting,
			&bulk_in, &bulk_out, NULL, NULL);
	if (retval) {
		dev_err(&interface->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	dev->bulk_in_size = usb_endpoint_maxp(bulk_in);
	dev->bulk_in_endpointAddr = bulk_in->bEndpointAddress;
	dev->bulk_in_buffer = kmalloc(dev->bulk_in_size, GFP_KERNEL);
	if (!dev->bulk_in_buffer) {
		retval = -ENOMEM;
		goto error;
	}
	dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->bulk_in_urb) {
		retval = -ENOMEM;
		goto error;
	}

	dev->bulk_out_endpointAddr = bulk_out->bEndpointAddress;

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, dev);

	/* we can register the device now, as it is ready */
	retval = usb_register_dev(interface, &ekm32_class);
	if (retval) {
		/* something prevented us from registering this driver */
		dev_err(&interface->dev,
			"Not able to get a minor for this device.\n");
		usb_set_intfdata(interface, NULL);
		goto error;
	}

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev,
		 "USB EKM32 device now attached to USBEKM32-%d",
		 interface->minor);

	return 0;

error:
	/* this frees allocated memory */
	kref_put(&dev->kref, ekm32_delete);

	return retval;
}

static void ekm32_disconnect(struct usb_interface *interface)
{
	struct usb_ekm32 *dev;
	int minor = interface->minor;
#ifdef DEBUG_EKM32
	printk("ekm32_disconnect"); // debug
#endif

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	/* give back our minor */
	usb_deregister_dev(interface, &ekm32_class);

	/* prevent more I/O from starting */
	mutex_lock(&dev->io_mutex);
	dev->interface = NULL;
	mutex_unlock(&dev->io_mutex);

	usb_kill_anchored_urbs(&dev->submitted);

	/* decrement our usage count */
	kref_put(&dev->kref, ekm32_delete);

	dev_info(&interface->dev, "USB ekm32 #%d now disconnected", minor);
}

static void ekm32_draw_down(struct usb_ekm32 *dev)
{
	int time;
#ifdef DEBUG_EKM32	
	printk("ekm32_draw_down"); // debug
#endif

	time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
	if (!time)
		usb_kill_anchored_urbs(&dev->submitted);
	usb_kill_urb(dev->bulk_in_urb);
}

static int ekm32_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usb_ekm32 *dev = usb_get_intfdata(intf);
#ifdef DEBUG_EKM32
	printk("ekm32_suspend"); // debug
#endif

	if (!dev)
		return 0;
	ekm32_draw_down(dev);
	return 0;
}

static int ekm32_resume(struct usb_interface *intf)
{
#ifdef DEBUG_EKM32	
	printk("ekm32_resume"); // debug
#endif
	return 0;
}

static int ekm32_pre_reset(struct usb_interface *intf)
{
	struct usb_ekm32 *dev = usb_get_intfdata(intf);
#ifdef DEBUG_EKM32
	printk("ekm32_pre_flush"); // debug
#endif

	mutex_lock(&dev->io_mutex);
	ekm32_draw_down(dev);

	return 0;
}

static int ekm32_post_reset(struct usb_interface *intf)
{
	struct usb_ekm32 *dev = usb_get_intfdata(intf);
#ifdef DEBUG_EKM32
	printk("ekm32_reset"); // debug
#endif

	/* we are sure no URBs are active - no locking needed */
	dev->errors = -EPIPE;
	mutex_unlock(&dev->io_mutex);

	return 0;
}

static struct usb_driver ekm32_driver = {
	.name =		"ekm32",
	.probe =	ekm32_probe,
	.disconnect =	ekm32_disconnect,
	.suspend =	ekm32_suspend,
	.resume =	ekm32_resume,
	.pre_reset =	ekm32_pre_reset,
	.post_reset =	ekm32_post_reset,
	.id_table =	ekm32_table,
	.supports_autosuspend = 1,
};

module_usb_driver(ekm32_driver);

MODULE_DESCRIPTION("ekm32");
MODULE_LICENSE("GPL");