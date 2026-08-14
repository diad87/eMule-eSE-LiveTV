'use strict';const assert=require('node:assert/strict');const test=require('node:test');const {createT8NetworkAdapter}=require('../v92_o01_t8_network_adapter');
test('network adapter exposes immediate controls and terminal cleanup',async()=>{let now=1000;const adapter=await createT8NetworkAdapter({mode:'NON_RELEASE',bindAddress:'127.0.0.1',now:()=>now});
 for(const fault of ['renew_success','expiry','epoch_reset']){const value=await adapter.inject(fault);assert.equal(value.gateway.foreign_fixture_present,true);}
 const final=await adapter.shutdown();assert.equal(final.product.publisher_active,false);assert.equal(final.product.journal_entry_count,0);assert.equal(final.gateway.mapping_count,1);
 await assert.rejects(adapter.observe(),/CLOSED/);
});
for(const fault of ['dropped_late','explicit_reject','stale','replay_duplicate','malformed','partial_pair','final_boundary'])test(`network adapter arms ${fault} exactly once`,async()=>{const adapter=await createT8NetworkAdapter({mode:'NON_RELEASE',bindAddress:'127.0.0.1',now:()=>1000});try{await adapter.inject(fault);await assert.rejects(adapter.inject(fault),/ARM_INVALID/);}finally{await adapter.shutdown();}});
test('formal network adapter fails closed before partial bind without provenance',async()=>{await assert.rejects(createT8NetworkAdapter({mode:'FORMAL_T8',bindAddress:'192.0.2.10',externalAddress:'88.11.22.4'}),/PROVENANCE/);await assert.rejects(createT8NetworkAdapter({mode:'FORMAL_T8',bindAddress:'192.0.2.10',externalAddress:'198.51.100.10'}),/EXTERNAL_ADDRESS/);});
