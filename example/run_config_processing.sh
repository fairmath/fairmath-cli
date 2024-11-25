#!/usr/bin/env bash

../.build/install/fairmath-cli \
--working_mode="config_processing" \
--input_config_location="./input.json" \
--output_crypto_objects_directory="." \
--output_config_location="./config.json" \
--output_config_json_indent="4"
