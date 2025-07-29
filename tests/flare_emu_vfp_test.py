import flare_emu
import sys

if __name__ == '__main__':
    # optional argument with sample path to test radare2 support
    if len(sys.argv) == 3:
        eh = flare_emu.EmuHelper(samplePath=sys.argv[1], isRizin=True)
    elif len(sys.argv) == 2:
        eh = flare_emu.EmuHelper(samplePath=sys.argv[1])
    else:
        eh = flare_emu.EmuHelper()
    print("testing VFP emulation")
    try:
        eh.emulateRange(0x460, 0x494, skipCalls=False)
        print("PASSED!")
    except:
        print("FAILED!")

