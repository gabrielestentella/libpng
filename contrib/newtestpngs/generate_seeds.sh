#!/bin/bash

SEED_DIR="seed_corpus_generated"
mkdir -p "$SEED_DIR"
echo "Generating seeds in $SEED_DIR..."

# --- Configuration ---

# data[0]: png_byte color_type = data[0] % 6;
# Values 0-5 to cover all possibilities.
# PNG_COLOR_TYPE_GRAY      0
# (Invalid type 1)         1
# PNG_COLOR_TYPE_RGB       2
# PNG_COLOR_TYPE_PALETTE   3
# PNG_COLOR_TYPE_GRAY_ALPHA 4
# (Invalid type 5, or maps to RGBA via %6 logic in some contexts) 5
declare -a COLOR_TYPES_RAW=(0 1 2 3 4 5)

# data[1]: png_byte bit_depth; switch (data[1] % 5) { case 0: 1; case 1: 2; ... case 4: 16; }
declare -a BIT_DEPTH_SELECTORS_RAW=(0 1 2 3 4)
# Direct array for bit depth values based on the selector index
declare -a BIT_DEPTH_VALUES=(1 2 4 8 16)

# data[2], data[3]: Used for png_uint_32 width = (*(png_uint_32*)(data + 2)) % 1024 + 1;
# We'll set a few (data[2], data[3]) pairs to get different base widths.
# Note: data[4] and data[5] are also part of this width calculation.
# With data[4] and data[5] being small (0-11 for data[4], 0-1 for data[5]),
# their contribution to (val % 1024) is often 0 for the higher bytes.
# So, width_raw % 1024 primarily comes from (data[3]<<8 | data[2]).
# (d2,d3) pairs for width:
# (0,0) -> raw_width_low_16bits = 0. Actual width approx 1.
# (15,0) -> raw_width_low_16bits = 15. Actual width approx 16.
# (255,0) -> raw_width_low_16bits = 255. Actual width approx 256.
# (255,3) -> raw_width_low_16bits = (3<<8)|255 = 768|255 = 1023. Actual width approx 1024.
declare -a WIDTH_CONFIGS=( "0,0" "15,0" "255,0" "255,3" )


# data[4]: uint8_t transform_type = data[4] % 12;
# We will iterate tt_raw from 0 to 11 directly for data[4].

# --- Helper Function to Write Seed ---
# --- Helper Function to Write Seed ---
write_seed_file() {
    local seed_bytes=("$@") # Receive array elements as positional arguments
    local width_tag
    local transform_tag
    local color_tag
    local bitdepth_sel_tag
    local variant_tag

    if (( ${#seed_bytes[@]} > 16 )); then
        width_tag="${seed_bytes[16]}"
    else
        width_tag=""
    fi

    if (( ${#seed_bytes[@]} > 17 )); then
        transform_tag="${seed_bytes[17]}"
    else
        transform_tag=""
    fi

    if (( ${#seed_bytes[@]} > 18 )); then
        color_tag="${seed_bytes[18]}"
    else
        color_tag=""
    fi

    if (( ${#seed_bytes[@]} > 19 )); then
        bitdepth_sel_tag="${seed_bytes[19]}"
    else
        bitdepth_sel_tag=""
    fi

    if (( ${#seed_bytes[@]} > 20 )); then
        variant_tag="${seed_bytes[20]}"
    else
        variant_tag=""
    fi

    local filename="${SEED_DIR}/seed_w${width_tag}_tt${transform_tag}_ct${color_tag}_bds${bitdepth_sel_tag}_${variant_tag}.png"

    # Basic check for byte values (0-255)
    for val in "${seed_bytes[@]:0:16}"; do # Check only the first 16 elements
        if (( val < 0 || val > 255 )); then
            echo "Error: Byte value out of range ($val) for $filename" >&2
            return 1
        fi
    done

    # To avoid excessive output, comment this out during large runs
    # printf "Writing: %s with bytes: %s\n" "$filename" "$(IFS=,; echo "${seed_bytes[@]:0:16}")"

    local byte_string=""
    for i in $(seq 0 15); do
        byte_string+=$(printf '\\x%02x' "${seed_bytes[$i]}")
    done
    printf "%b" "$byte_string" > "$filename"
}

# --- Main Generation Loop ---

for wc_pair in "${WIDTH_CONFIGS[@]}"; do
  IFS=',' read -r d2_val d3_val <<< "$wc_pair"
  current_width_tag="${d2_val}-${d3_val}"

  for tt_raw in {0..11}; do # data[4] directly, will be tt_raw % 12 in fuzzer
    for ct_raw in "${COLOR_TYPES_RAW[@]}"; do # data[0]
      for bds_raw in "${BIT_DEPTH_SELECTORS_RAW[@]}"; do # data[1]
        # Directly get the bit depth from the array
        actual_bit_depth=${BIT_DEPTH_VALUES[$bds_raw]}

        # Initialize 16 bytes for the seed
        declare -a seed_bytes=(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
        seed_bytes[0]=$ct_raw
        seed_bytes[1]=$bds_raw
        seed_bytes[2]=$d2_val
        seed_bytes[3]=$d3_val
        seed_bytes[4]=$tt_raw
        # seed_bytes[5-15] are initially 0

        # --- Handle transform-specific parameter variations for data[5] and data[6-8] ---
        is_generic_case=1 # Flag to check if specific logic handled this combo

        # Case 0: png_do_bgr - No specific extra params from data[5-8]
        # Case 1: png_do_invert - No specific extra params
        # Case 2: png_do_packswap - No specific extra params
        # Case 3: png_do_swap - No specific extra params

        if [ "$tt_raw" -eq 4 ] || [ "$tt_raw" -eq 5 ]; then # strip_channel / filler
          is_generic_case=0
          # data[5] is used as a boolean (data[5]%2)
          if [ "$tt_raw" -eq 5 ]; then # PNG_FILLER: needs color_type == PNG_COLOR_TYPE_RGB (2) or PNG_COLOR_TYPE_GRAY (0)
            if ! ([ "$ct_raw" -eq 0 ] || [ "$ct_raw" -eq 2 ]); then
                continue # Skip if color type not Gray or RGB for filler
            fi
          fi
          for cond1_val in 0 1; do # Iterate the boolean flag for data[5]
            seed_bytes[5]=$cond1_val
            seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0; # Reset others
            write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "d5cond_${cond1_val}"
          done

        elif [ "$tt_raw" -eq 6 ] || [ "$tt_raw" -eq 7 ]; then # png_do_swap_alpha / png_do_invert_alpha
          is_generic_case=0
          # Needs color_type & PNG_COLOR_MASK_ALPHA (which is color_type & 4)
          # True if color_type is 4 or 5 (since data[0]%6 -> color_type means ct_raw=4 -> 4, ct_raw=5 -> 5)
          if ! ([ "$ct_raw" -eq 4 ] || [ "$ct_raw" -eq 5 ]); then
              continue
          fi
          seed_bytes[5]=0; seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0; # Default data[5-8]
          write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "alpha_op"

        elif [ "$tt_raw" -eq 8 ]; then # png_do_check_palette_indexes
          is_generic_case=0
          # Needs color_type == PNG_COLOR_TYPE_PALETTE (3) && bit_depth < 8
          if ! ([ "$ct_raw" -eq 3 ] && [ "$actual_bit_depth" -lt 8 ]); then
              continue
          fi
          seed_bytes[5]=0; seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0;
          write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "palette_check"

        elif [ "$tt_raw" -eq 9 ]; then # Test interlace handling
          is_generic_case=0
          # data[5] used as a boolean (data[5]%2)
          for cond1_val in 0 1; do
            seed_bytes[5]=$cond1_val
            seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0;
            write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "interlace_${cond1_val}"
          done

        elif [ "$tt_raw" -eq 10 ]; then # Test packing
          is_generic_case=0
          # Needs bit_depth < 8
          if [ "$actual_bit_depth" -ge 8 ]; then
              continue
          fi
          seed_bytes[5]=0; seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0;
          write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "pack_op"

        elif [ "$tt_raw" -eq 11 ]; then # Test shift
          is_generic_case=0
          # Needs bit_depth < 8. Uses data[5-8] for shift values.
          # shift.comp = data[X] % (1 << bit_depth)
          if [ "$actual_bit_depth" -ge 8 ]; then
              continue
          fi
          # Test two simple sets of raw data bytes for shift: all 0s, all 1s
          # These will result in shift amounts 0 or 1 for each channel component.
          declare -a shift_byte_sets=( "0,0,0,0" "1,1,1,1" )
          for sbs_csv in "${shift_byte_sets[@]}"; do
            IFS=',' read -r d5_s d6_s d7_s d8_s <<< "$sbs_csv"
            seed_bytes[5]=$d5_s
            seed_bytes[6]=$d6_s
            seed_bytes[7]=$d7_s
            seed_bytes[8]=$d8_s
            write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "shift_${d5_s}${d6_s}${d7_s}${d8_s}"
          done
        fi

        # For transforms 0, 1, 2, 3 or any combo not specifically creating seeds above
        if [ "$is_generic_case" -eq 1 ]; then
          seed_bytes[5]=0; seed_bytes[6]=0; seed_bytes[7]=0; seed_bytes[8]=0; # Ensure defaults
          write_seed_file "${seed_bytes[@]}" "$current_width_tag" "$tt_raw" "$ct_raw" "$bds_raw" "generic_default"
        fi

      done # bds_raw
    done # ct_raw
  done # tt_raw
done # wc_pair

echo "Seed generation complete. ${#WIDTH_CONFIGS[@]} width configs processed."
echo "Total files (approx): consider the product of loops and conditional branches."