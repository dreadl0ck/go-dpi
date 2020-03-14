# TODO

## Windows

cross compile for windows fails:

    godpi_example $ GCCFLAGS="-I/usr/local/opt/libpcap/include -I/usr/local/Cellar/liblinear/2.30/include" LDFLAGS="-L/usr/local/opt/libpcap/lib -L/usr/local/Cellar/liblinear/2.30/lib" CGO_ENABLED=1 CC=/usr/local/Cellar/mingw-w64/7.0.0_1/bin/x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build
    # github.com/dreadl0ck/go-dpi/modules/ml
    /usr/local/Cellar/mingw-w64/7.0.0_1/toolchain-x86_64/bin/x86_64-w64-mingw32-ld: cannot find -llinear
    collect2: error: ld returned 1 exit status
    # github.com/dreadl0ck/go-dpi/modules/wrappers
    ld: warning: ignoring file $WORK/b126/_cgo_main.o, building for macOS-x86_64 but attempting to link with file built for unknown-unsupported file format ( 0x64 0x86 0x10 0x00 0x00 0x00 0x00 0x00 0x5C 0x0B 0x00 0x00 0x2A 0x00 0x00 0x00 )
    ld: warning: ignoring file $WORK/b126/_x001.o, building for macOS-x86_64 but attempting to link with file built for unknown-unsupported file format ( 0x64 0x86 0x09 0x00 0x00 0x00 0x00 0x00 0xCA 0x05 0x00 0x00 0x12 0x00 0x00 0x00 )
    ld: warning: ignoring file $WORK/b126/_x002.o, building for macOS-x86_64 but attempting to link with file built for unknown-unsupported file format ( 0x64 0x86 0x0D 0x00 0x00 0x00 0x00 0x00 0x16 0x1A 0x00 0x00 0x2A 0x00 0x00 0x00 )
    ld: warning: ignoring file $WORK/b126/_x003.o, building for macOS-x86_64 but attempting to link with file built for unknown-unsupported file format ( 0x64 0x86 0x0D 0x00 0x00 0x00 0x00 0x00 0x70 0x63 0x00 0x00 0x28 0x00 0x00 0x00 )
    ld: warning: ignoring file $WORK/b126/_x004.o, building for macOS-x86_64 but attempting to link with file built for unknown-unsupported file format ( 0x64 0x86 0x11 0x00 0x00 0x00 0x00 0x00 0x1C 0xCF 0x00 0x00 0x3F 0x00 0x00 0x00 )
    Undefined symbols for architecture x86_64:
    "_main", referenced from:
        implicit entry/start for main executable
    ld: symbol(s) not found for architecture x86_64
    clang: error: linker command failed with exit code 1 (use -v to see invocation)