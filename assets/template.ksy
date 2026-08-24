# Kaitai Struct skeleton for a paged / record-oriented format.
# Compile:  kaitai-struct-compiler -t python format.ksy
# Or paste into the Kaitai Web IDE to render a parse tree over a hex view.
#
# Replace every <> placeholder. Delete what does not apply. Keep the doc
# strings: a spec that records *why* a field is believed to be what it is
# is worth far more than one that only records the offsets.

meta:
  id: <format_name>
  title: <Human readable name>
  file-extension: <ext>
  endian: le            # confirm with fieldmap.py before trusting this
  encoding: UTF-16LE    # default text encoding; override per field as needed

doc: |
  Reverse engineered from <N> samples, producer versions <list>.
  Fields marked INFERRED in the doc strings have not been confirmed by a
  controlled mutation. See the hypothesis ledger for status and support.

seq:
  - id: pages
    type: page
    repeat: eos

types:
  page:
    seq:
      - id: magic
        contents: [0xcd, 0xab, 0xcc, 0xac]   # ESTABLISHED: constant across corpus
        doc: Page signature.

      - id: page_id
        type: u4
        doc: ESTABLISHED. Strictly increments by 1; confirmed by trial A.

      - id: page_type
        type: u2
        enum: page_types

      - id: record_count
        type: u2
        doc: INFERRED. Matches the number of TOC entries in every sample.

      - id: reserved
        size: 4
        doc: UNKNOWN. Always zero in this corpus; may be used by other versions.

      - id: timestamp
        type: u8
        doc: |
          INFERRED. Decodes as Windows FILETIME. Semantics undetermined --
          it is not established which event sets it, or whether it is UTC.

      - id: checksum
        type: u4
        doc: ESTABLISHED. CRC-32/ISO-HDLC over bytes 32..end of page.

      - id: data_offset
        type: u4

      - id: padding
        size: 32 - 32     # adjust to your header size

      - id: toc
        type: toc_entry
        repeat: expr
        repeat-expr: record_count

    instances:
      # Resolve pointers here. If the format has a logical-to-physical page
      # map, that translation cannot be expressed in pure Kaitai -- do it in
      # the host language and pass resolved offsets in as parameters.
      body:
        pos: data_offset
        size-eos: true

  toc_entry:
    seq:
      - id: record_id
        type: u4
      - id: offset
        type: u4
        doc: Offset within this page. INFERRED -- see ledger row.
      - id: length
        type: u4
      - id: crc
        type: u4
        doc: |
          May be present but unused on some producer versions. Do not treat a
          zero value as corruption without checking the version first.

  prefixed_string:
    doc: Length-prefixed, prefix counts BYTES, not characters. No terminator.
    seq:
      - id: len_bytes
        type: u4
      - id: value
        type: str
        size: len_bytes
        encoding: UTF-16LE

enums:
  page_types:
    0x0001: type_a
    0x0002: type_b
