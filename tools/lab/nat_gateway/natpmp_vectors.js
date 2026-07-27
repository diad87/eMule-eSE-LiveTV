'use strict';

/**
 * C01 NAT-PMP wire goldens.  These are inert data copied from the native
 * codec tests and implementation; this module deliberately contains no
 * encoder, decoder, socket, timer, or I/O behavior.
 */
const NATPMP_VECTORS = Object.freeze({
  external_address_request: Object.freeze({
    hex: '0000',
    length: 2,
    derivation: 'PRODUCTIVE_CODEC',
    provenance: Object.freeze([
      'libnatmap/src/natpmp_codec.cpp:34-40',
    ]),
  }),
  external_address_response: Object.freeze({
    hex: '008000000000002a580b1604',
    length: 12,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:63-75',
    ]),
  }),
  map_tcp_request: Object.freeze({
    hex: '00020000123601bb00001c20',
    length: 12,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:25-31',
    ]),
  }),
  map_udp_request: Object.freeze({
    hex: '00010000123601bb00001c20',
    length: 12,
    derivation: 'DERIVED_FROM_PRODUCTIVE_CONSTANT',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:25-31',
      'libnatmap/include/natmap/natpmp_codec.h:8-11',
      'libnatmap/src/natpmp_codec.cpp:69-74',
    ]),
  }),
  map_tcp_response: Object.freeze({
    hex: '00820000000000631236cbb000000e10',
    length: 16,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:37-47',
    ]),
  }),
  map_tcp_delete_request: Object.freeze({
    hex: '000200001236000000000000',
    length: 12,
    derivation: 'DERIVED_FROM_PRODUCTIVE_CONSTANT',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:33-35',
      'libnatmap/src/natpmp_codec.cpp:69-74',
    ]),
  }),
});

module.exports = Object.freeze({ NATPMP_VECTORS });
