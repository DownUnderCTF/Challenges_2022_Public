# build nana first
clang++ artisan.cpp -o artisan -O2 -std=c++17 -stdlib=libc++ -Ithird_party/nana/include -Lthird_party/nana/build/bin -lnana -lX11 -lXcursor -lpthread -lrt -lXft -lfontconfig -lc++ -lstdc++fs
strip ./artisan
