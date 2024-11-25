#!/usr/bin/env bash

../.build/install/fairmath-cli \
--working_mode="ciphertext_decryption" \
--output_decryption_location="./output_decryption" \
--decryption_cryptocontext_location="./cryptocontext_name" \
--ciphertext_location="./ciphertext_1" \
--decryption_key_location="./private_key_name" \
--plaintext_length="10"
