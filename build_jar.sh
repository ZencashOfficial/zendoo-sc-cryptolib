cargo clean

cargo build --release --target=x86_64-pc-windows-gnu
cargo build --release --target=x86_64-unknown-linux-gnu


mkdir -p jni/src/main/resources/native/linux64
cp target/x86_64-unknown-linux-gnu/release/libzendoo_sc.so jni/src/main/resources/native/linux64/libzendoo_sc.so

mkdir -p jni/src/main/resources/native/windows64
cp target/x86_64-pc-windows-gnu/release/zendoo_sc.dll jni/src/main/resources/native/windows64/zendoo_sc.dll
# copy windows specific dependencies for rocksdb
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll jni/src/main/resources/native/windows64/libwinpthread-1.dll
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-posix/libgcc_s_seh-1.dll jni/src/main/resources/native/windows64/libgcc_s_seh-1.dll
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-posix/libstdc++-6.dll jni/src/main/resources/native/windows64/libstdc++-6.dll


cd jni
mvn clean package
