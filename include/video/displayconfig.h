/*
 * Defines array containing list of all available/known displays and related physical parameters.
 *
 * Copyright (C) 2013 Exor International
 * Author: Giovanni Pavoni (Exor)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
 /*
 * HISTORY REVISION
 * Version  Signature       Date      	Modification reason		
 * 1.0  		SS							08.07.14		Started from displayconfig_rev2.00.xml; the min backlight is set to minimum value supported by the hw (display as
 *																			on US01 there is NO support of the gamma correction and therefor the min backlight value might be different from 
 *																			the value used on Serie500 (displayconfig.xml file).
 * 1.1			SS              25.08.14    Alligned to displayconfog_rev2.2.1.xml:
 *																			Display code #48: changed max brightness to 70%
 *																			Display code #46: changed max brightness to 100%
 *																			Display code #47: changed max brightness to 100%
 *																			Added display code #49: 7" Rocktech for ECO
 * 1.2			SS              12.09.14    Alligned to displayconfog_rev2.2.2.xml:
 *																			Added display code #50: 10" Rocktech for ECO
 * 						              18.09.14    Alligned to displayconfog_rev2.3.1.xml:
 *																			Display code #46: changed horizontal back porch to 39
 * 1.3			SS              17.02.15    Alligned to displayconfog_rev2.3.2.xml:
 *																			Added display code #51: 4,3" Rocktech for ECO
 * 1.4			SS              24.02.15    On displayconfog_rev2.3.3.xml we removed all ECO/LINUX displays; no allignement will be performed.
 *																			Added display code #52: for Altera kit, same code as #31 but MAX brightness=100% 
 *																			Changed on display code #47 .pclk_freq = 64000 (original 72000): otherwise it will not work on Altera kit
 * 1.5			SS              13.04.15    Changed on display code #51 .pclk_freq = 12000 (original 9000): Linux driver is now generating 12MHz, please check OS driver 
 *                                      in order to generate pclk freq lower than 12MHz with proper accurancy!
 *																			As the eSMART04 has been certified with 12MHz pixel clock setting, this is kept also for future fixes into the OS driver.
 * 1.6			GP              13.04.16    Added display code #55: Innolux G101ICE-L01 LVDS 24 bit 1280x800 for serie 700
 *
 * 1.7			GP              23.05.16    Added display code #56: Innolux G156BGE-L01 LVDS 24 bit 1366x768 for serie 700
 *                                                  Added display code #57: Innolux G215HVN01 LVDS 24 bit 1920x1080 for serie 700
 *                                                  Added display code #58: DataImage 7" LVDS 24 bit 800x480 for serie 700
 * 1.8	    SS  	   				07.11.2016  Alligned to displayconfig_rev2.5.xml:
 *																			Inverted display clock edge for LVDS drivers wrongly set on next HDAxx carrier boards  
 *																			HDA02A: display codes #36,38,39: inverted clock polarity   
 *																			HDA05A: display codes #45 (OLD glass display): inverted clock polarity 
 * 1.9	    GP  	   				02.02.2017  Added gamma correction for display codes #55 and #58, required tuning of min brite to allow 0,5cd/m2 on step0:
 *																			display code #55: modified min brite from 1 to 10 (0,5cd/m2 for step0)
 *																			display code #58: modified min brite from 10 to 20 (0,5cd/m2 for step0)
 *1.10			SS							27.03.2017  Modified all display codes used by IMX.6 CPU (US03Ax) due to bug on LVDS clock (refer to unfuddle ticket #650).
 *																			Display codes 55, 56, 57 and 58 HAVE TO BE USED only on IMX.6 panels!!!!
 *																			display code #55: modified pixel clock from 0 to 1
 *																			display code #56: modified pixel clock from 0 to 1
 *																			display code #57: modified pixel clock from 0 to 1
 *																			display code #58: modified pixel clock from 0 to 1; modified hs_w from 100 to 200 as per typical datasheet value (no visible effect)
 *1.11			SS							20.04.2017  Added display code #59: FutureLabs  FLT-070D07-W0 800x480 High Brightness for WE16
 *																			Added display code #60: CHIMEI TG070Y2-L01 800x480 for WE16 using both US01Ax and US03Ax
 *1.12			SS							01.09.2017  Added display code #61: FutureLabs 1024x600 High Brightness for Jsmart07---Initial definition without any datasheet/spec
 *1.13			SS							05.09.2017  Added display code #62: FutureLabs 1280x800 High Brightness for Jsmart10---Initial definition without any datasheet/spec
 *1.14			SS							20.09.2017  Added display code #63: FutureLabs FLT-1001Q2ETTXNH01 1280x800 for serie 700 High Brightness 
 *1.15			SS							30.10.2017  Added display code #64: Qitex QX-050WVGA0TLT00D 800x480 for ex705-rocktouch 
 *1.16			SS							21.11.2017  Added display code #65: FutureLabs FLT-BB070MR02-YO 800x480 for ex707-HB-rocktouch 
 *1.17			SS							17.01.2018  Added display code #66: DISPJST-005N001 800x480 for Jsmart05---Initial definition 
 *1.18			SS							28.03.2018  Modified display code #64: modified pixel clock from 1 to 0 due to wrong datasheet info
 *1.19			SS							09.07.2018  Added display code #67: FutureLabs FLC-101HML0000SA2 for ex710-hb
 *1.20			SS							25.09.2018  Modified display code #66: DISPJST-005N001 800x480 for Jsmart05, Max duty 70% in order to reduce brite to about 300cd/m2
 *1.21			SS							03.10.2018  Modified display code #63: FutureLabs FLC-101HML0000SA2 for ex710-hb and pixel clock set to min (66.6MHz) to avoid vertical green
 *										line when driving with grey pattern (190,190,190)
 *1.22			SS							18.01.2019  Modified display code #66: DISPJST-005N001 800x480 for Jsmart05, modified pixel clock from 0 to 1 due to wrong datasheet info
 *1.23			SS							24.01.2019  Modified display code #63: FutureLabs FLC-101HML0000SA2 for ex710-hb changed vertical and horizontal porches as per datasheet timings
 *										to avoid vertical green line when driving with grey pattern (190,190,190)
 *1.24			SS							18.02.2019  Added display code #68: Qitex QX-050WVGA0TLT01D 800x480 for ex705
 *1.25			GP							04/2019	    Added display code #69 Futurelabs FLC-1234ML3000SA1 Dual LVDS 24 bit 1920x720
 *1.26			GP							05/2019	    Updated the brightness_min field for ticket BSP-1559
 *1.27			GP							05/2019	    Updated the brightness_min field for ticket BSP-1559 on display code #65, #55
 *1.28			SS							17.06.2019  Added display code #70: Innolux G156HCE-L01 LVDS 24 bit 1920x1080 for serie jSMART
 *1.29			SS							28.06.2019	Modified display code #51:Updated the brightness_min (0.07%) and PWM (6kHz) fields for ticket BSP-1559
 *1.30			SS							11.07.2019	Modified display code #36: for AB19 display 10" G104AGE-L02
 *												Modified display code #39: for AB19 display 15" G150XNE-L01
 *1.31			GP							17.07.2019	Added display code #71 for the TA19 target (same as display code #63 but with 100% max. dimm)
 *1.32			GP							17.07.2019	Added display code #72: FutureLabs FLC-070DMTK000SA1 800x480 for ex707-HB. Changed max brightness for code #69
 *1.33			GP							09.01.2020	Changed pwm freq. and min brightness for code #69
 *1.34			SS							17.01.2020	Changed pwm freq. for code #57
 *1.35			SS							27.02.2020	Added display code #73: Multi-Inno MI0500AHT-5CP 800x480 for WE20-5inch.
 *1.36			SS							27.07.2020	Added display code #74: Multi-Inno  MI1210RT-2 1280x800 for WE20-12inch.
 *1.37			SS							27.11.2020	Added display code #75: Futurelabs  FLC-101HML0000SA2-V1 1280x800 for WE20-10inch.
 *														          Added display code #76: Innolux  G121ICE-L01 1280x800 for WE20-12 ONLY.
 *1.38			SS							02.12.2020	Added display code #77: DMB T050800480-A9WMC-002 800x480 for WE20-5inch.
 *1.39			SS							11.12.2020	Changed pwm freq. for code #75: 10kHz because the DIMM is used also by the keyboard leds driven by TPS61165
 *1.40			SS							22.07.2021	Modified display code #70:HT1560EI01AC5 (eX715MG), min duty using LT3754 set to 0,08%
 *1.41			SS							27.09.2021	Changed pwm freq. for code #75: 5kHz and min duty to 1% to match datasheet minimum backlight spec and still drive keyboard leds
 *1.42			SS							04.03.2022	Added display code #78: DMB T070102600-B3WMN-001 for DAH21 (1024x600).
 *1.43			SS							22.08.2022	Added display code #79: Futurelabs FLC070DML02 (800x480 serie700).
 *1.44			SS							26.09.2022	Added display code #80: Futurelabs FLR-101HML00PUFA2#02 (1280x800 WE20-10).
 *1.45			SS							27.09.2022	Added display code #81: same as display #76 but dimming positive (new carrier WU10A1)
 *			 								27.09.2022	Added display code #82: Futurelabs FLD-121GML20PC001#00 (Innolux G121XCE-L01) for GE22 (1024x768) 
 *1.46			SS							05.10.2022	Added display code #83: 
 *1.47			GP							02.02.2023	Added display code #84: DMB KD101WXFLD038-C045B (10.1", 1280x800) for SE21 X10 handheld 
 *1.48			SS							01.03.2023	Added display code #85: Futurelabs DISPJST-101N002#01 for new jSMART10x 
 *1.49			SS							02.03.2023	Modified display code #71: changed porches to match latest display datasheet specs
 *1.50			SS							19.05.2023	Added display code #86: Futurelabs FLC-101HMLG000003#00 for new eX710G 
 *													26.05.2023	Modified display code #70: DISPHT1560EI011 (HT1560EI01A) for eX715MG (1920x1080)
 *                                      reduced min duty to reach zero-dimming on imx8 for eX715MG
 *1.51			SS							15.06.2023	Modified display code #85: MAX duty set to 100% for 700cd/m2 as old jSMART10, pcn describes wrong 400cd/m2 spec
 *1.52			SS							20.11.2023	Added display code #87: Yes YTCA10WLBC-07-100C-V2 eSMART02-10" 
 *														Added display code #88: Yes YTC700TLBF-13-200C-V1 eSMART02-7", only datasheet spec no real test
 *														Added display code #89: Yes YTC500RLBH-42-200C eSMART02-5", only datasheet spec no real test
 *														Added display code #90: Innolux G156HCE-LN1 eSMART02-15", only datasheet spec no real test
 *1.53          GP                          14.12.2023  Modified display code #87 to use same timings of #86, since they use the same controller chip.
 *                                                      Modified display code #56 to use different hfp value with imx8mm, to get proper timings with the sn65dsi8x mipi2lvds bridge.
 *1.54          GP                          09.01.2024  Added display code #91: Futurelabs FLC-101HMLG200002#00 for eX710
 *1.55          GP                          30.01.2024  Updated max duty value for display codes 87, 88, 89, (eSMARt02 5, 7, 10"") according to updated specs.
 *
 * NEXT AVAILABLE DISPLAY CODE: 92
 */
 
#ifndef DISPLAYCONFIG_H
#define DISPLAYCONFIG_H

#define NODISPLAY 0xffff

/* -----------------------------------------------------------
structure which describes the LCD parameters
-----------------------------------------------------------*/
struct t_DisplayParams{
  unsigned long dispid;                           // Display id
  unsigned short brightness_min, brightness_max;  // Inverter's minimum and maximum brightness 	(expressed as pwm dutycycle; range 0...100)
  unsigned long pwmfreq;                          // Frequency of PWM controller [Hz]
  unsigned long rezx, rezy, bpp;                  // Resolution and bpp
  unsigned long hs_fp, hs_bp, hs_w, hs_inv;       // Hsync params
  unsigned long vs_fp, vs_bp, vs_w, vs_inv;       // Vsync params
  unsigned long blank_inv;                        // Blank params
  unsigned long pclk_freq, pclk_inv;              // Pixel clock params (f in Khz)
};

/* 
 * Add to this list any further display device description
 * NOTE: Please remember the last element works as terminator and MUST have the .dispid=NODISPLAY
 */
static struct t_DisplayParams displayconfig[] = {
    /* 25: Powertip PS480272T-005-I11Q 480x272*/
    {
        .dispid    = 25,
        .rezx      = 480, 
        .rezy      = 272, 
        .bpp       = 16,
        
        .pclk_freq = 12000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 3, 
        .hs_bp     = 1, 
        .hs_w      = 41, 
        .hs_inv    = 1,
        
        .vs_fp     = 1, 
        .vs_bp     = 3, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 50,
    },
    /* 31: Evervision VGG804806_HSE03_PWM 800x480*/
    {
        .dispid    = 31,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 60,
    },
    /* 32: CHIMEI TG070Y2-L01 800x480*/
    {
        .dispid    = 32,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 20,
        .brightness_max = 100,
    },
    /* 36: Innolux G104AGE-L02 800x600 for AB19*/
    {
        .dispid    = 36,
        .rezx      = 800, 
        .rezy      = 600, 
        .bpp       = 16,
        
        .pclk_freq = 36000, 
        .pclk_inv  = 1,
        
        .hs_fp     = 16, 
        .hs_bp     = 149, 
        .hs_w      = 69, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 36, 
        .vs_w      = 7, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 2,
        .brightness_max = 100,
    },
    /* 37: Powertip 320x240 */
    {
        .dispid    = 37,
        .rezx      = 320, 
        .rezy      = 240, 
        .bpp       = 16,
        
        .pclk_freq = 8000,  
        .pclk_inv  = 1,
        
        .hs_fp     = 20, 
        .hs_bp     = 38, 
        .hs_w      = 30, 
        .hs_inv    = 1,
        
        .vs_fp     = 5, 
        .vs_bp     = 15, 
        .vs_w      = 4, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 60,
    },
    /* 38: AUO G121SN01V4 800x600*/
    {
        .dispid    = 38,
        .rezx      = 800, 
        .rezy      = 600, 
        .bpp       = 16,
        
        .pclk_freq = 36000, 
        .pclk_inv  = 1,
        
        .hs_fp     = 16, 
        .hs_bp     = 149, 
        .hs_w      = 69, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 36, 
        .vs_w      = 7, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 5,
        .brightness_max = 100,
    },
    /* 39: Innolux G150XNE-L01 1024x768 for AB19*/
    {
        .dispid    = 39,
        .rezx      = 1024, 
        .rezy      = 768, 
        .bpp       = 16,
        
        .pclk_freq = 61000, 
        .pclk_inv  = 1,
        
        .hs_fp     = 16, 
        .hs_bp     = 149, 
        .hs_w      = 69, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 36, 
        .vs_w      = 7, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 1,
        .brightness_max = 100,
    },
    /* 40: Innolux AT050TN33 480x272*/
    {
        .dispid    = 40,
        .rezx      = 480, 
        .rezy      = 272, 
        .bpp       = 16,
        
        .pclk_freq = 12000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 3, 
        .hs_bp     = 1, 
        .hs_w      = 41, 
        .hs_inv    = 1,
        
        .vs_fp     = 1, 
        .vs_bp     = 3, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 100,
    },
    /* 41: Chimei G133IGE-L03 1280x800*/
    {
        .dispid    = 41,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 16,
        
        .pclk_freq = 72000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 11, 
        .hs_bp     = 110, 
        .hs_w      = 50, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 28, 
        .vs_w      = 11, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 4000,
        .brightness_min = 10,
        .brightness_max = 65,
    },
    /* 42: Chimei G121I1-L01 1280x800*/
    {
	.dispid    = 42,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 16,
        
        .pclk_freq = 72000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 11, 
        .hs_bp     = 221, 
        .hs_w      = 101, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 28, 
        .vs_w      = 11, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 10,
        .brightness_max = 100,
    },
    /* 43: Ampire AM-800480R2TMQW-T02H 800x480*/
    {
        .dispid    = 43,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 28000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 60,
    },
    /* 44: Tianma TM043NBH02 480x272*/
    {
        .dispid    = 44,
        .rezx      = 480, 
        .rezy      = 272, 
        .bpp       = 16,
        
        .pclk_freq = 12000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 3, 
        .hs_bp     = 1, 
        .hs_w      = 41, 
        .hs_inv    = 1,
        
        .vs_fp     = 1, 
        .vs_bp     = 3, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 50,
    },
    /* 45: AGL VM15B2 V4 1024x768 15" */
    {
        .dispid    = 45,
        .rezx      = 1024, 
        .rezy      = 768, 
        .bpp       = 16,
        
        .pclk_freq = 72000, 
        .pclk_inv  = 1,
        
        .hs_fp     = 16, 
        .hs_bp     = 149, 
        .hs_w      = 69, 
        .hs_inv    = 1,
        
        .vs_fp     = 2, 
        .vs_bp     = 36, 
        .vs_w      = 7, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 2,
        .brightness_max = 80,
    },
    /* 46: TIANMA TM050RDH03 800x480 */
    {
      .dispid    = 46,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 16,
      
      .pclk_freq = 27000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 40, 
      .hs_bp     = 39, 
      .hs_w      = 48, 
      .hs_inv    = 1,
      
      .vs_fp     = 13, 
      .vs_bp     = 30, 
      .vs_w      = 3, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 10000,
      .brightness_min = 1,
      .brightness_max = 100,
    },
    /* 47: AUO G101EVN01.0 1280x800 */
    {
      .dispid    = 47,
      .rezx      = 1280, 
      .rezy      = 800, 
      .bpp       = 16,
      
      .pclk_freq = 64000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 11, 
      .hs_bp     = 110, 
      .hs_w      = 50, 
      .hs_inv    = 1,
      
      .vs_fp     = 2, 
      .vs_bp     = 28, 
      .vs_w      = 11, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 4000,
      .brightness_min = 5,
      .brightness_max = 100,
    },    
    /* 48: Evervision VGG804806 for eTOP607 800x480 */
    {
      .dispid    = 48,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 16,
      
      .pclk_freq = 30000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 41, 
      .hs_bp     = 35, 
      .hs_w      = 129, 
      .hs_inv    = 1,
      
      .vs_fp     = 12, 
      .vs_bp     = 35, 
      .vs_w      = 3, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 10000,
      .brightness_min = 1,
      .brightness_max = 70,
    },   
    /* 49: Rocktech RK070EH1401-T 800x480*/
    {
        .dispid    = 49,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 205, 
        .hs_bp     = 46, 
        .hs_w      = 3, 
        .hs_inv    = 1,
        
        .vs_fp     = 20, 
        .vs_bp     = 23, 
        .vs_w      = 2, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 0x1900,	/* BSP-1559 : Brightness min. = 0.25% */
        .brightness_max = 100,
    },     
    /* 50: Rocktech RK101EH1401-T 1024x600*/
    {
        .dispid    = 50,
        .rezx      = 1024, 
        .rezy      = 600, 
        .bpp       = 16,
        
        .pclk_freq = 51000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 10, 
        .hs_bp     = 320, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 10, 
        .vs_bp     = 35, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 0x2800,	/* BSP-1559 : Brightness min. = 0.40% */
        .brightness_max = 100,
    },  
		/* 51: Rocktech RK043EH1401-T 480x272*/
    {
        .dispid    = 51,
        .rezx      = 480, 
        .rezy      = 272, 
        .bpp       = 16,
        
        .pclk_freq = 12000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 8, 
        .hs_bp     = 43, 
        .hs_w      = 1, 
        .hs_inv    = 1,
        
        .vs_fp     = 4, 
        .vs_bp     = 12, 
        .vs_w      = 1, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 6000,
        .brightness_min = 0x0700,	/* BSP-1559 : Brightness min=0.07% */
        .brightness_max = 80,
    },  
    /* 52: Evervision VGG804806_PWM for ALTERA kit 800x480*/
    {
        .dispid    = 52,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 0,
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 100,
    },  
    /* 55: Innolux G101ICE-L01 LVDS 24 bit 1280x800 IMX.6 ONLY */
    {
        .dispid    = 55,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 71100, 
        .pclk_inv  = 1,				//27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 30, 
        .hs_bp     = 30, 
        .hs_w      = 100, 
        .hs_inv    = 0,
        
        .vs_fp     = 3, 
        .vs_bp     = 10, 
        .vs_w      = 10, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 0x3200, 		/* BSP-1559 : Brightness min=0.50% */
        .brightness_max = 100,
    },              
    /* 56: Innolux G156BGE-L01 LVDS 24 bit 1366x768 IMX.6 ONLY */
    {
        .dispid    = 56,
        .rezx      = 1366, 
        .rezy      = 768, 
        .bpp       = 24,
        
        .pclk_freq = 76000, 
        .pclk_inv  = 1,		     //27.03.2017 inverted clock polarity due to IMX.6 bug

#ifdef CONFIG_SOC_IMX6Q
        .hs_fp     = 47,
#else
        .hs_fp     = 12,
#endif
        .hs_bp     = 47,
        .hs_w      = 100,
        .hs_inv    = 0,
        
        .vs_fp     = 9, 
        .vs_bp     = 9, 
        .vs_w      = 20, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 10,
        .brightness_max = 100,
    },              
    /* 57: Innolux G215HVN01 DUAL LVDS 24 bit 1920x1080 IMX.6 ONLY*/
    {
        .dispid    = 57,
        .rezx      = 1920, 
        .rezy      = 1080, 
        .bpp       = 24,
        
        .pclk_freq = 72000,  // DUAL LVDS dispaly: this is the freq. of one single channel
        .pclk_inv  = 1,			 //27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 40, 
        .hs_bp     = 40, 
        .hs_w      = 120, 
        .hs_inv    = 0,
        
        .vs_fp     = 5, 
        .vs_bp     = 5, 
        .vs_w      = 30, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 20000,	//17.01.2020 changed from 250Hz to 20kHz
        .brightness_min = 10,
        .brightness_max = 100,
    },              
    /* 58: DataImage 7" LVDS 24 bit 800x480 */
    {
        .dispid    = 58,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 24,
        
        .pclk_freq = 33200,  
        .pclk_inv  = 1,			//27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 28, 
        .hs_bp     = 28, 
        .hs_w      = 200, 
        .hs_inv    = 0,
        
        .vs_fp     = 10, 
        .vs_bp     = 10, 
        .vs_w      = 25, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 250,
        .brightness_min = 20,
        .brightness_max = 100,
    }, 
    /* 59: FutureLabs  FLT-070D07-W0 800x480 High Brightness*/
    {
        .dispid    = 59,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 1,	//20.04.2017 inverted clock polarity due to IMX.6 bug; for US01Ax TTL will drive the display lines on falling edge => LVDS driver needs to sample on rising edge
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,  //20.04.2017 backlight driven by TPS61165
        .brightness_min = 1,
        .brightness_max = 100,
    }, 
    /* 60: CHIMEI TG070Y2-L01 800x480 for WE16 using both US01Ax and US03Ax*/
    {
        .dispid    = 60,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 1,	//20.04.2017 inverted clock polarity due to IMX.6 bug; for US01Ax TTL will drive the display lines on falling edge => LVDS driver needs to sample on rising edge
        
        .hs_fp     = 41, 
        .hs_bp     = 35, 
        .hs_w      = 129, 
        .hs_inv    = 1,
        
        .vs_fp     = 12, 
        .vs_bp     = 35, 
        .vs_w      = 3, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,  
        .brightness_min = 20,
        .brightness_max = 100,
    }, 
    /* 61: FutureLabs Jsmart07 1024x600 IMX.6 ONLY*/
    {
        .dispid    = 61,
        .rezx      = 1024, 
        .rezy      = 600, 
        .bpp       = 24,
        
        .pclk_freq = 51000, 
        .pclk_inv  = 1,  // inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 10, 
        .hs_bp     = 320, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 10, 
        .vs_bp     = 35, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 10,
        .brightness_max = 100,
    },
    /* 62: FutureLabs Jsmart10 LVDS 24 bit 1280x800 IMX.6 ONLY */
    {
        .dispid    = 62,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 71100, 
        .pclk_inv  = 1,		// inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 30, 
        .hs_bp     = 30, 
        .hs_w      = 100, 
        .hs_inv    = 0,
        
        .vs_fp     = 3, 
        .vs_bp     = 10, 
        .vs_w      = 10, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 10,
        .brightness_max = 100,
    },   
    /* 63: FutureLabs FLC-101HML0000SA2 24 bit 1280x800 IMX.6 ONLY */
    {
        .dispid    = 63,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         //03.10.2018 min freq to avoid green line
        .pclk_inv  = 1,				//inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 12,            //24.01.2019 SS
        .hs_bp     = 88,            //24.01.2019 SS
        .hs_w      = 1,             //24.01.2019 SS
        .hs_inv    = 0,
        
        .vs_fp     = 1,             //24.01.2019 SS
        .vs_bp     = 23,            //24.01.2019 SS
        .vs_w      = 1,             //24.01.2019 SS
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 10,
        .brightness_max = 80,
    },  
     /* 64: QITEX QX-050WVGA0TLT00D 800x480 */
    {
      .dispid    = 64,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 16,
      
      .pclk_freq = 27000, 
      .pclk_inv  = 0,           //28.03.2018 inverted clock polarity due to datasheet error
      
      .hs_fp     = 40, 
      .hs_bp     = 40, 
      .hs_w      = 48, 
      .hs_inv    = 1,
      
      .vs_fp     = 13, 
      .vs_bp     = 29, 
      .vs_w      = 3, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 10000,
      .brightness_min = 1,
      .brightness_max = 100,
    }, 
    /* 65: FutureLabs  FLT-BB070MR02-YO 800x480 ex707-High Brightness IMX.6 ONLY*/
    {
        .dispid    = 65,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 24,
        
        .pclk_freq = 29000, 
        .pclk_inv  = 1,	//21.11.2017 inverted clock polarity due to IMX.6 bug; 
        
        .hs_fp     = 25, 
        .hs_bp     = 25, 
        .hs_w      = 78, 
        .hs_inv    = 0,
        
        .vs_fp     = 5, 
        .vs_bp     = 5, 
        .vs_w      = 35, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,  
        .brightness_min = 0x0F00, 		/* BSP-1559 : Brightness min=0.15% */
        .brightness_max = 100,
    },   
    /* 66:DISPJST-005N001 800x480 for Jsmart05 */
    {
        .dispid    = 66,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 30000, 
        .pclk_inv  = 1,         //18.01.2019 inverted clock due to initial error in datasheet
        
        .hs_fp     = 210, 
        .hs_bp     = 23, 
        .hs_w      = 23, 
        .hs_inv    = 1,
        
        .vs_fp     = 22, 
        .vs_bp     = 11, 
        .vs_w      = 12, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 10,
        .brightness_max = 70,
    }, 
    /* 67: FutureLabs FLC-101HML0000SA2 LVDS 24 bit 1280x800 IMX.6 ONLY */
    {
        .dispid    = 67,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 71100, 
        .pclk_inv  = 1,				//27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 30, 
        .hs_bp     = 30, 
        .hs_w      = 100, 
        .hs_inv    = 0,
        
        .vs_fp     = 3, 
        .vs_bp     = 10, 
        .vs_w      = 10, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 10,
        .brightness_max = 70,
    }, 
    /* 68: QITEX QX-050WVGA0TLT01D 800x480 */
    {
        .dispid    = 68,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 16,
        
        .pclk_freq = 27000, 
        .pclk_inv  = 0,           
        
        .hs_fp     = 16, 
        .hs_bp     = 46, 
        .hs_w      = 1, 
        .hs_inv    = 0,
        
        .vs_fp     = 7, 
        .vs_bp     = 23, 
        .vs_w      = 1, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 100,
      },                                                             
    /* 69: Futurelabs  FLC-1234ML3000SA1 DUAL LVDS 24 bit 1920x720 IMX.6 ONLY*/
    {
        .dispid    = 69,
        .rezx      = 1920, 
        .rezy      = 720, 
        .bpp       = 24,
        
        .pclk_freq = 44100,  // DUAL LVDS dispaly: this is the freq. of one single channel
        .pclk_inv  = 1,			 //27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 32, 
        .hs_bp     = 16, 
        .hs_w      = 16, 
        .hs_inv    = 1,
        
        .vs_fp     = 16, 
        .vs_bp     = 3, 
        .vs_w      = 2, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 0x0F00, 		/* Brightness min=0.15% */
        .brightness_max = 85,
    }, 
    /* 70: HTDisplay HT1560EI01A DUAL LVDS 24 bit 1920x1080 eX715MG*/
    {
        .dispid    = 70,
        .rezx      = 1920, 
        .rezy      = 1080, 
        .bpp       = 24,
        
        .pclk_freq = 70930,      // DUAL LVDS dispaly: this is the freq. of one single channel
        .pclk_inv  = 1,			 		//27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 15, 
        .hs_bp     = 90, 
        .hs_w      = 1, 
        .hs_inv    = 0,
        
        .vs_fp     = 10, 
        .vs_bp     = 20, 
        .vs_w      = 1, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 0x0300,		//min duty 0,03%
        .brightness_max = 100,
    },                               
    /* 71: FutureLabs FLC-101HML0000SA2 24 bit 1280x800 IMX.6 ONLY for TA19 */
    {
        .dispid    = 71,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         //03.10.2018 min freq to avoid green line
        .pclk_inv  = 1,				//inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 12,            //24.01.2019 SS
        .hs_bp     = 86,            //02.03.2023 SS
        .hs_w      = 2,             //02.03.2023 SS
        .hs_inv    = 0,
        
        .vs_fp     = 1,             //24.01.2019 SS
        .vs_bp     = 3,             //02.03.2023 SS
        .vs_w      = 20,            //02.03.2023 SS
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 10,
        .brightness_max = 100,
    },  
    /* 72: FutureLabs  FLC-070DMTK000SA1 800x480 ex707-High Brightness IMX.6 ONLY*/
    {
        .dispid    = 72,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 24,
        
        .pclk_freq = 29000, 
        .pclk_inv  = 1,	//21.11.2017 inverted clock polarity due to IMX.6 bug; 
        
        .hs_fp     = 60, 
        .hs_bp     = 32, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 60, 
        .vs_bp     = 5, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 6000,  
        .brightness_min = 0x0800, 		/* BSP-1559 : Brightness min=0.08% */
        .brightness_max = 90,
    },
    /* 73: MULTI-INNO MI0500AHT-5CP 800x480 */
    {
      .dispid    = 73,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 16,
      
      .pclk_freq = 27000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 48, 
      .hs_bp     = 48, 
      .hs_w      = 8, 
      .hs_inv    = 1,
      
      .vs_fp     = 12, 
      .vs_bp     = 12, 
      .vs_w      = 8, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 10000,
      .brightness_min = 1,
      .brightness_max = 50,
    },   
    /* 74: Multiinno  MI1210RT-2 24 bit 1280x800 IMX.6 compatible */
    {
        .dispid    = 74,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         
        .pclk_inv  = 1,					//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 12,            
        .hs_bp     = 88,            
        .hs_w      = 1,             
        .hs_inv    = 0,
        
        .vs_fp     = 1,             
        .vs_bp     = 23,            
        .vs_w      = 1,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 1,
        .brightness_max = 100,
    },
        /* 75: Futurelabs  FLC-101HML0000SA2-V1 1280x800 for WE20-10inch */
    {
        .dispid    = 75,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 62600,         //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)
        .pclk_inv  = 1,							//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 15,            
        .hs_bp     = 5,            
        .hs_w      = 1,             
        .hs_inv    = 0,
        
        .vs_fp     = 3,             
        .vs_bp     = 2,            
        .vs_w      = 1,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 5000,	//27.09.2021 keyboard led dimming driven by TPS61165
        .brightness_min = 1,		//27.09.2021 min duty cycle as per new datasheet by Futurelabs
        .brightness_max = 45,
    },    
     /* 76: Innolux  G121ICE-L01 1280x800 for WE20-12 ONLY */
    {
        .dispid    = 76,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 71000,     //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)   
        .pclk_inv  = 1,					//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 70,            
        .hs_bp     = 70,            
        .hs_w      = 20,             
        .hs_inv    = 0,
        
        .vs_fp     = 10,             
        .vs_bp     = 10,            
        .vs_w      = 3,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 5,
        .brightness_max = 0x0146, 	//gestione inversione polarità PWM dimming (segno): 0x01nn=segno; 0x46= 70 (MAX dimm)
    },
        /* 77: DMB T050800480-A9WMC-002 800x480 */
    {
      .dispid    = 77,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 16,
      
      .pclk_freq = 27000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 48, 
      .hs_bp     = 48, 
      .hs_w      = 8, 
      .hs_inv    = 1,
      
      .vs_fp     = 12, 
      .vs_bp     = 12, 
      .vs_w      = 8, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 10000,
      .brightness_min = 1,
      .brightness_max = 80,
    },  
    /* 78: DMB T070102600-B3WMN-001 for DAH21 1024x600*/
    {
        .dispid    = 78,
        .rezx      = 1024, 
        .rezy      = 600, 
        .bpp       = 24,
        
        .pclk_freq = 51000, 
        .pclk_inv  = 1,  // inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 10, 
        .hs_bp     = 300, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 10, 
        .vs_bp     = 15, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 10000,
        .brightness_min = 1,
        .brightness_max = 100,
    },
    /* 79: FutureLabs  FLC070DML02 800x480 ex707 IMX.6 ONLY*/
    {
        .dispid    = 79,
        .rezx      = 800, 
        .rezy      = 480, 
        .bpp       = 24,
        
        .pclk_freq = 29000, 
        .pclk_inv  = 1,	//21.11.2017 inverted clock polarity due to IMX.6 bug; 
        
        .hs_fp     = 60, 
        .hs_bp     = 32, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 60, 
        .vs_bp     = 5, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,  
        .brightness_min = 0x6400, 		/* BSP-1559 : Brightness min=1% */
        .brightness_max = 100,
    }, 
    /* 80: Futurelabs  FLR-101HML00PUFA2#02 1280x800 for WE20-10inch new carrier (WU10A1) */
    {
        .dispid    = 80,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)
        .pclk_inv  = 1,							//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 12,            
        .hs_bp     = 86,            
        .hs_w      = 2,             
        .hs_inv    = 0,
        
        .vs_fp     = 1,             
        .vs_bp     = 3,            
        .vs_w      = 20,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 6500,			//27.09.2022 keyboard led dimming driven by TPS61165 (avoid EasyScale min freq)
        .brightness_min = 0x3200,		//27.09.2022 min duty cycle 0.5%
        .brightness_max = 40,
    },    
    /* 81: Innolux  G121ICE-L01 1280x800 for WE20-12 PWM polarity=positive, new carrier (WU10A1) */
    {
        .dispid    = 81,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 71000,     //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)   
        .pclk_inv  = 1,					//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 70,            
        .hs_bp     = 70,            
        .hs_w      = 20,             
        .hs_inv    = 0,
        
        .vs_fp     = 10,             
        .vs_bp     = 10,            
        .vs_w      = 3,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 5,
        .brightness_max = 70, 	//polarità PWM dimming positiva
    },
    /* 82: Futurelabs FLD-121GML20PC001#00 (Innolux G121XCE-L01) for GE22 */
    {
        .dispid    = 82,
        .rezx      = 1024, 
        .rezy      = 768, 
        .bpp       = 24,
        
        .pclk_freq = 71000,         //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)
        .pclk_inv  = 1,							//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 150,            
        .hs_bp     = 150,            
        .hs_w      = 20,             
        .hs_inv    = 0,
        
        .vs_fp     = 15,             
        .vs_bp     = 15,            
        .vs_w      = 8,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,			
        .brightness_min = 1,		
        .brightness_max = 100,
    },
    /* 83: FutureLabs FLC-070FMLG000002#00 for WE22*/
    {
        .dispid    = 83,
        .rezx      = 1024, 
        .rezy      = 600, 
        .bpp       = 24,
        
        .pclk_freq = 51000, 
        .pclk_inv  = 1,  // inverted clock polarity due SN65LVDS93 CLKSEL high (sample on rising edge)
        
        .hs_fp     = 10, 
        .hs_bp     = 320, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 10, 
        .vs_bp     = 35, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 6500,			//keyboard led dimming driven by TPS61165 (avoid EasyScale min freq)
        .brightness_min = 0x3200,		//min duty cycle 0.5%
        .brightness_max = 80,
    },    
    /* 84: DMB KD101WXFLD038-C045B (10.1", 1280x800) for SE21 X10 handheld  */
    {
        .dispid    = 84,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)
        .pclk_inv  = 1,							//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 12,            
        .hs_bp     = 86,            
        .hs_w      = 2,             
        .hs_inv    = 0,
        
        .vs_fp     = 1,             
        .vs_bp     = 3,            
        .vs_w      = 20,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 5000,		//Backlight controller is TPS61500PWPR, analog mode. 5Khz is TI suggested freq. for 1uF Cdimc value.
        .brightness_min = 1,		//min duty cycle 1% as per TI recommendation
        .brightness_max = 65,
    },    
    /* 85: Futurelabs DISPJST-101N002#01 (10.1", 1280x800) for new jSMART10x  */
    {
        .dispid    = 85,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         //US04 supporta un numero limitato di freq (fare sempre check con tabella PLL)
        .pclk_inv  = 1,							//inverted clock polarity (compatibility with IMX.6 bug)
        
        .hs_fp     = 12,            
        .hs_bp     = 86,            
        .hs_w      = 2,             
        .hs_inv    = 0,
        
        .vs_fp     = 1,             
        .vs_bp     = 3,            
        .vs_w      = 20,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 6500,			//TPS61165 (avoid EasyScale min freq)
        .brightness_min = 0x3200,		//min duty cycle 0.5%
        .brightness_max = 100,				//MAX duty set to 100% 
    }, 
    /* 86: FutureLabs FLC-101HMLG000003#00 24 bit 1280x800 (exact timing required) */
    {
        .dispid    = 86,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,
        
        .pclk_freq = 66600,         
        .pclk_inv  = 1,							//inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 12,            
        .hs_bp     = 86,            
        .hs_w      = 2,             
        .hs_inv    = 0,
        
        .vs_fp     = 1,             
        .vs_bp     = 3,            
        .vs_w      = 20,             
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,          //LT3754
#ifdef CONFIG_SOC_IMX6Q		
        .brightness_min = 0x1000,       //min duty 0,15%
        .brightness_max = 100,
#else
        .brightness_min = 0x0300,       //min duty 0,03% on US04 (no gamma correction)
        .brightness_max = 100,          //max duty 100% on US04 
#endif
    },  
    /* 87: Yes YTCA10WLBC-07-100C-V2(10.1", 1280x800) for eSMART02  */
    {
        .dispid    = 87,
        .rezx      = 1280, 
        .rezy      = 800, 
        .bpp       = 24,

        .pclk_freq = 66600,
        .pclk_inv  = 1,							//inverted clock polarity due to IMX.6 bug

        .hs_fp     = 12,
        .hs_bp     = 86,
        .hs_w      = 2,
        .hs_inv    = 0,

        .vs_fp     = 1,
        .vs_bp     = 3,
        .vs_w      = 20,
        .vs_inv    = 0,

        .blank_inv      = 0,
        
        .pwmfreq        = 5000,				//Backlight controller is TPS61500PWPR, analog mode. 5Khz is TI suggested freq. for 1uF Cdimc value.
        .brightness_min = 0x6300,		 //min duty cycle 0.99% 
        .brightness_max = 70,
    },   
    /* 88: YES YTC700TLBF-13-200C-V1 for eSMART02-7" 1024x600*/
    {
        .dispid    = 88,
        .rezx      = 1024, 
        .rezy      = 600, 
        .bpp       = 24,
        
        .pclk_freq = 51000, 
        .pclk_inv  = 1,  // inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 10, 
        .hs_bp     = 320, 
        .hs_w      = 10, 
        .hs_inv    = 1,
        
        .vs_fp     = 10, 
        .vs_bp     = 35, 
        .vs_w      = 10, 
        .vs_inv    = 1,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 5000,				//Backlight controller is TPS61500PWPR, analog mode. 5Khz is TI suggested freq. for 1uF Cdimc value.
        .brightness_min = 0x6300,		 //min duty cycle 0.99% 
        .brightness_max = 70,
    },   
    /* 89: YES YTC500RLBH-42-200C for eSMART02-5" 800x480 */
    {
      .dispid    = 89,
      .rezx      = 800, 
      .rezy      = 480, 
      .bpp       = 24,
      
      .pclk_freq = 27000, 
      .pclk_inv  = 0,
      
      .hs_fp     = 48, 
      .hs_bp     = 48, 
      .hs_w      = 8, 
      .hs_inv    = 1,
      
      .vs_fp     = 12, 
      .vs_bp     = 12, 
      .vs_w      = 8, 
      .vs_inv    = 1,
      
      .blank_inv      = 0,
      
      .pwmfreq        = 6500,			//27.09.2022 keyboard led dimming driven by TPS61165 (avoid EasyScale min freq)
      .brightness_min = 0x6300,		 //min duty cycle 0.99%
      .brightness_max = 70,
    },   
    /* 90: Innolux G156HCE-LN1 DUAL LVDS 24 bit 1920x1080 eSMART02-15"*/
    {
        .dispid    = 90,
        .rezx      = 1920, 
        .rezy      = 1080, 
        .bpp       = 24,
        
        .pclk_freq = 70930,      // DUAL LVDS dispaly: this is the freq. of one single channel
        .pclk_inv  = 1,			 		//27.03.2017 inverted clock polarity due to IMX.6 bug
        
        .hs_fp     = 15, 
        .hs_bp     = 90, 
        .hs_w      = 1, 
        .hs_inv    = 0,
        
        .vs_fp     = 10, 
        .vs_bp     = 20, 
        .vs_w      = 1, 
        .vs_inv    = 0,
        
        .blank_inv      = 0,
        
        .pwmfreq        = 200,
        .brightness_min = 5,		
        .brightness_max = 100,
    },                     
    /* 91: FutureLabs FLC-101HMLG200002#00 24 bit 1280x800 (exact timing required) */
    {
        .dispid    = 91,
        .rezx      = 1280,
        .rezy      = 800,
        .bpp       = 24,

        .pclk_freq = 66600,
        .pclk_inv  = 1,							//inverted clock polarity due to IMX.6 bug

        .hs_fp     = 12,
        .hs_bp     = 86,
        .hs_w      = 2,
        .hs_inv    = 0,

        .vs_fp     = 1,
        .vs_bp     = 3,
        .vs_w      = 20,
        .vs_inv    = 0,

        .blank_inv      = 0,

        .pwmfreq        = 200,
        .brightness_min = 0x6300,		//min duty 0,99%
        .brightness_max = 100,
    },
    /* END OF LIST */
    {
      .dispid    = NODISPLAY,
      .rezx      = NODISPLAY, 
      .rezy      = NODISPLAY, 
      .bpp       = NODISPLAY,
      
      .pclk_freq = NODISPLAY, 
      .pclk_inv  = NODISPLAY,
      
      .hs_fp     = NODISPLAY, 
      .hs_bp     = NODISPLAY, 
      .hs_w      = NODISPLAY, 
      .hs_inv    = NODISPLAY,
      
      .vs_fp     = NODISPLAY, 
      .vs_bp     = NODISPLAY, 
      .vs_w      = NODISPLAY, 
      .vs_inv    = NODISPLAY,
      
      .blank_inv      = NODISPLAY,
      
      .pwmfreq        = NODISPLAY,
      .brightness_min = NODISPLAY,
      .brightness_max = NODISPLAY,
    },
    
};

#endif
