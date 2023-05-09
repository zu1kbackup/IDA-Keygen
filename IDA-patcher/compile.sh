# Configure below
target="IDA Pro 7.7" # the one you want to compile

# Installing dependencies
sudo apt-get install dietlibc-dev gcc-mingw-w64

# Compile target
cd "$target"
make && make patch && make "../ida_key.exe" && make "../patch_ida.exe"
