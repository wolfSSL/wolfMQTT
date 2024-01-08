echo NOTICE: This used the experimental sparse checkout.
echo See https://git-scm.com/docs/git-sparse-checkout/2.37.0
echo and https://github.blog/2020-01-17-bring-your-monorepo-down-to-size-with-sparse-checkout/
echo ""
echo  intialize...
git init

echo remote origin https://github.com/wolfSSL/wolfMQTT.git
git remote add origin https://github.com/wolfSSL/wolfMQTT.git

echo setting fetch depth = 1
git fetch --depth 1

echo enabling sparse checkout to limit only files for this component
git config core.sparsecheckout true

echo  it seems only when all parameters are on the git sparse-checkout command does this do what is desired to include and exclude proprly:
git sparse-checkout set  /src/ /test/ /wolfMQTT/ /wolfcrypt/ !/wolfcrypt/src/*.S !/wolfcrypt/src/*.asm /wolfcrypt/src/port/Espressif/ /wolfcrypt/src/port/atmel/  

echo checking out master branch....
git checkout -b master

echo  by the time we get here, we should be excluding everything except those items
echo  of interest for the wolfMQTT component
git pull origin master

mkdir include
git show master:IDE/Espressif/ESP-IDF/user_settings.h     > include/user_settings.h
git show master:IDE/Espressif/ESP-IDF/libs/CMakeLists.txt > CMakeLists.txt
git show master:IDE/Espressif/ESP-IDF/libs/component.mk   > component.mk

echo wolfMQTT installed!