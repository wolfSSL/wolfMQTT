function(override_cache VAR VAL)
    get_property(VAR_STRINGS CACHE ${VAR} PROPERTY STRINGS)
    LIST(FIND VAR_STRINGS ${VAL} CK)
    if(-1 EQUAL ${CK})
        message(SEND_ERROR
            "\"${VAL}\" is not valid override value for \"${VAR}\"."
            " Please select value from \"${VAR_STRINGS}\"\n")
    endif()
    set_property(CACHE ${VAR} PROPERTY VALUE ${VAL})
endfunction()

function(add_option NAME HELP_STRING DEFAULT VALUES)
    # Set the default value for the option.
    set(${NAME} ${DEFAULT} CACHE STRING ${HELP_STRING})
    # Set the list of allowed values for the option.
    set_property(CACHE ${NAME} PROPERTY STRINGS ${VALUES})

    if(DEFINED ${NAME})
        list(FIND VALUES ${${NAME}} IDX)
        #
        # If the given value isn't in the list of allowed values for the option,
        # reduce it to yes/no according to CMake's "if" logic:
        # https://cmake.org/cmake/help/latest/command/if.html#basic-expressions
        #
        # This has no functional impact; it just makes the settings in
        # CMakeCache.txt and cmake-gui easier to read.
        #
        if (${IDX} EQUAL -1)
            if(${${NAME}})
                override_cache(${NAME} "yes")
            else()
                override_cache(${NAME} "no")
            endif()
        endif()
    endif()
endfunction()

function(add_to_options_file DEFINITIONS OPTION_FILE)
    list(REMOVE_DUPLICATES DEFINITIONS)
    foreach(DEF IN LISTS DEFINITIONS)
        if(DEF MATCHES "^-D")
            if(DEF MATCHES "^-D(N)?DEBUG(=.+)?")
                message("not outputting (N)DEBUG to ${OPTION_FILE}")
            endif()

            # allow user to ignore system options
            if(DEF MATCHES "^-D_.*")
                file(APPEND ${OPTION_FILE} "#ifndef WOLFSSL_OPTIONS_IGNORE_SYS\n")
            endif()

            string(REGEX REPLACE "^-D" "" DEF_NO_PREFIX ${DEF})
            string(REGEX REPLACE "=.*$" "" DEF_NO_EQUAL_NO_VAL ${DEF_NO_PREFIX})
            string(REPLACE "=" " " DEF_NO_EQUAL ${DEF_NO_PREFIX})

            file(APPEND ${OPTION_FILE} "#undef  ${DEF_NO_EQUAL_NO_VAL}\n")
            file(APPEND ${OPTION_FILE} "#define ${DEF_NO_EQUAL}\n")

            if(DEF MATCHES "^-D_.*")
                file(APPEND ${OPTION_FILE} "#endif\n")
            endif()

            file(APPEND ${OPTION_FILE} "\n")
        endif()
    endforeach()
endfunction()
