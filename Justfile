set quiet := true
set shell := ["bash", "-c"]
emulator_dir := 'coinkite/coinkite-tap-proto/emulator'

# list of recipes
default:
  just --list

# format the project code
fmt:
    cargo +nightly fmt --all

# lint the project
clippy: fmt
    cargo clippy --all-features --all-targets

# build the project
build: fmt
    cargo build --all-features --all-targets

# setup the cktap emulator venv
setup:
    (test -d emulator_env || python3 -m venv emulator_env) && \
    source emulator_env/bin/activate; pip install -r {{emulator_dir}}/requirements.txt > /dev/null 2>&1

# get cktap emulator options help
help:
    source emulator_env/bin/activate; python3 coinkite/coinkite-tap-proto/emulator/ecard.py emulate --help

# start the cktap emulator on /tmp/ecard-pipe
start *OPTS: setup
    if [ -f emulator_env/ecard.pid ]; then \
        echo "Emulator already running, pid:" `cat emulator_env/ecard.pid`; \
    else \
        source emulator_env/bin/activate; python3 coinkite/coinkite-tap-proto/emulator/ecard.py emulate {{OPTS}} &> emulator_env/output.log & \
        echo $! > emulator_env/ecard.pid; \
        echo "started emulator, pid:" `cat emulator_env/ecard.pid`; \
    fi

# stop the cktap emulator
stop:
    if [ -f emulator_env/ecard.pid ]; then \
        echo "killing emulator, pid:" `cat emulator_env/ecard.pid`; \
        kill `cat emulator_env/ecard.pid` && rm emulator_env/ecard.pid; \
    else \
        echo "emulator pid file not found."; \
    fi

# test the rust-cktap lib with the coinkite cktap card emulator
test: fmt setup
    source emulator_env/bin/activate && cargo test -p rust-cktap --features emulator -- --nocapture

# clean the project target directory
clean:
    cargo clean

# run the cli locally with a usb pcsc card reader (HID OMNIKEY 5022 CL Rev:C)
run *CMD:
    cargo run -p cktap-cli {{CMD}}

# run the cli locally with an emulated satscard (see start and stop recipes)
run_emu *CMD:
    cargo run -p cktap-cli --features emulator -- {{CMD}}
