# Component wolfSSL

This `wolfssl` directory exists only for the stand-alone examples.

The only files of interest are the [CMakeLists.txt](./CMakeLists.txt) that should point
to the wolfSSL source code and the respective [include/user_settings.h](./include/user_settings.h).

This directory is _not_ included in the publish to the Espressif Registry, as that
mechanism copies the published source code to the local component directory as needed. 
