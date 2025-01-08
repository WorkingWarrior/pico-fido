import os
import shutil
import subprocess
import multiprocessing

VERSION_MAJOR = "6"
VERSION_MINOR = "0"
SUFFIX = f"{VERSION_MAJOR}.{VERSION_MINOR}"

# Clean and create directories
if os.path.exists("release"):
    shutil.rmtree("release")
os.makedirs("release", exist_ok=True)
os.makedirs("build_release", exist_ok=True)
os.chdir("build_release")

boards = [
    "0xcb_helios",
    "adafruit_feather_rp2040_usb_host",
    "adafruit_feather_rp2040",
    "adafruit_itsybitsy_rp2040",
    "adafruit_kb2040",
    "adafruit_macropad_rp2040",
    "adafruit_qtpy_rp2040",
    "adafruit_trinkey_qt2040",
    "amethyst_fpga",
    "archi",
    "arduino_nano_rp2040_connect",
    "cytron_maker_pi_rp2040",
    "datanoisetv_rp2040_dsp",
    "eetree_gamekit_rp2040",
    "garatronic_pybstick26_rp2040",
    "gen4_rp2350_24",
    "gen4_rp2350_24ct",
    "gen4_rp2350_24t",
    "gen4_rp2350_28",
    "gen4_rp2350_28ct",
    "gen4_rp2350_28t",
    "gen4_rp2350_32",
    "gen4_rp2350_32ct",
    "gen4_rp2350_32t",
    "gen4_rp2350_35",
    "gen4_rp2350_35ct",
    "gen4_rp2350_35t",
    "hellbender_2350A_devboard",
    "ilabs_challenger_rp2350_bconnect",
    "ilabs_challenger_rp2350_wifi_ble",
    "ilabs_opendec02",
    "melopero_perpetuo_rp2350_lora",
    "melopero_shake_rp2040",
    "metrotech_xerxes_rp2040",
    "net8086_usb_interposer",
    "nullbits_bit_c_pro",
    "phyx_rick_tny_rp2350",
    "pi-plates_micropi",
    "pico",
    "pico_w",
    "pico2",
    "pimoroni_badger2040",
    "pimoroni_interstate75",
    "pimoroni_keybow2040",
    "pimoroni_motor2040",
    "pimoroni_pga2040",
    "pimoroni_pga2350",
    "pimoroni_pico_plus2_rp2350",
    "pimoroni_picolipo_4mb",
    "pimoroni_picolipo_16mb",
    "pimoroni_picosystem",
    "pimoroni_plasma2040",
    "pimoroni_plasma2350",
    "pimoroni_servo2040",
    "pimoroni_tiny2040",
    "pimoroni_tiny2040_2mb",
    "pimoroni_tiny2350",
    "pololu_3pi_2040_robot",
    "pololu_zumo_2040_robot",
    "seeed_xiao_rp2040",
    "seeed_xiao_rp2350",
    "solderparty_rp2040_stamp",
    "solderparty_rp2040_stamp_carrier",
    "solderparty_rp2040_stamp_round_carrier",
    "solderparty_rp2350_stamp_xl",
    "solderparty_rp2350_stamp",
    "sparkfun_micromod",
    "sparkfun_promicro",
    "sparkfun_promicro_rp2350",
    "sparkfun_thingplus",
    "switchscience_picossci2_conta_base",
    "switchscience_picossci2_dev_board",
    "switchscience_picossci2_micro",
    "switchscience_picossci2_rp2350_breakout",
    "switchscience_picossci2_tiny",
    "tinycircuits_thumby_color_rp2350",
    "vgaboard",
    "waveshare_rp2040_lcd_0.96",
    "waveshare_rp2040_lcd_1.28",
    "waveshare_rp2040_one",
    "waveshare_rp2040_plus_4mb",
    "waveshare_rp2040_plus_16mb",
    "waveshare_rp2040_zero",
    "weact_studio_rp2040_2mb",
    "weact_studio_rp2040_4mb",
    "weact_studio_rp2040_8mb",
    "weact_studio_rp2040_16mb",
    "wiznet_w5100s_evb_pico"
]

for board in boards:
    # Clean directory
    for item in os.listdir("."):
        if os.path.isfile(item):
            os.remove(item)
        elif os.path.isdir(item):
            shutil.rmtree(item)

    # Set SDK path
    sdk_path = os.environ.get("PICO_SDK_PATH", "../../pico-sdk")
    os.environ["PICO_SDK_PATH"] = sdk_path

    # Build
    subprocess.run(["cmake", "..", f"-DPICO_BOARD={board}"], check=True)
    subprocess.run(["make", f"-j{multiprocessing.cpu_count()}"], check=True)
    
    # Move result
    shutil.move("pico_fido.uf2", f"../release/pico_fido_{board}-{SUFFIX}.uf2")
