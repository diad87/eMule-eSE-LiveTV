'use strict';

/**
 * D01 PCP wire goldens. These are inert literals copied from values assembled
 * by the native codec tests and productive codec. No encoder, decoder, socket,
 * timer, random source, or productive implementation is imported here.
 */
const PCP_VECTORS = Object.freeze({
  map_tcp_request: Object.freeze({
    hex: '0201000000001c2000000000000000000000ffffc0a801140102030405060708090a0b0c06000000123601bb00000000000000000000000000000000',
    length: 60,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:78-105',
      'libnatmap/src/pcp_codec.cpp:69-102',
    ]),
  }),
  map_tcp_renewal_request: Object.freeze({
    hex: '0201000000001c2000000000000000000000ffffc0a801140102030405060708090a0b0c06000000123601bb00000000000000000000ffff580b1604',
    length: 60,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:107-111',
      'libnatmap/src/pcp_codec.cpp:69-102',
    ]),
  }),
  map_native_v6_request: Object.freeze({
    hex: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db8000100020000000000000040',
    length: 60,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:113-121',
      'libnatmap/src/pcp_codec.cpp:69-102',
    ]),
  }),
  map_prefer_failure_request: Object.freeze({
    hex: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db800010002000000000000004002000000',
    length: 64,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:123-126',
      'libnatmap/src/pcp_codec.cpp:103-107',
    ]),
  }),
  map_port_set_request: Object.freeze({
    hex: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db8000100020000000000000040820000050020123601000000',
    length: 72,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:128-136',
      'libnatmap/src/pcp_codec.cpp:108-115',
    ]),
  }),
  map_tcp_delete_request: Object.freeze({
    hex: '020100000000000020010db80001000200000000000000200102030405060708090a0b0c060000001236000000000000000000000000000000000000',
    length: 60,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:138-144',
      'libnatmap/src/pcp_codec.cpp:92-100',
    ]),
  }),
  map_tcp_response: Object.freeze({
    hex: '0281000000000e10000004d20000000000000000000000000102030405060708090a0b0c060000001236cbb000000000000000000000ffff580b1604820000050020123601000000',
    length: 72,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:147-170',
      'libnatmap/src/pcp_codec.cpp:118-176',
    ]),
  }),
  announce_request: Object.freeze({
    hex: '020000000000000000000000000000000000ffffc0a80114',
    length: 24,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:194-199',
      'libnatmap/src/pcp_codec.cpp:57-67',
    ]),
  }),
  announce_response: Object.freeze({
    hex: '028000020000000000002694000000000000000000000000',
    length: 24,
    derivation: 'EXISTING_TEST_VECTOR',
    provenance: Object.freeze([
      'libnatmap/tests/test_mapping_codecs.cpp:199-208',
      'libnatmap/src/pcp_codec.cpp:180-199',
    ]),
  }),
});

module.exports = Object.freeze({ PCP_VECTORS });
