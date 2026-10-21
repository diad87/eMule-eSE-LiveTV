param([Parameter(Mandatory=$true)][string]$ProfileRoot,
      [ValidateRange(1,180)][int]$TimeoutSeconds=150)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $ProfileRoot).Path
if(!$root.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Only a prepared D:\tmp profile is permitted.' }
$ancestor=Get-Item -LiteralPath $root
while($ancestor) {
    if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile ancestors cannot be reparse points.' }
    $ancestor=$ancestor.Parent
}
foreach($relative in @('config','config\preferences.ini','emule.exe','prepared.json')) {
    if((Get-Item -LiteralPath (Join-Path $root $relative)).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile inputs cannot be reparse points.' }
}
foreach($relative in @('started.json','runtime-evidence.json','process-id.txt','logs')) {
    if(Test-Path -LiteralPath (Join-Path $root $relative)) { throw "Profile already used: $relative" }
}
$manifest=Get-Content -LiteralPath (Join-Path $root 'prepared.json') -Raw | ConvertFrom-Json
if($manifest.schema -ne 'ese.v93.reach-binding-lab/1' -or $manifest.profile -ne $root) { throw 'Wrong preparation manifest.' }
$diagnosticPort=if($manifest.PSObject.Properties.Name -contains 'diagnostic_web_port'){[int]$manifest.diagnostic_web_port}else{0}
if($diagnosticPort -and ($diagnosticPort -lt 1024 -or $diagnosticPort -gt 65535 -or $diagnosticPort -in @($manifest.tcp,$manifest.udp))) { throw 'Unsafe diagnostic port.' }
if($diagnosticPort -and (Get-FileHash -LiteralPath (Join-Path $root 'eMule.tmpl')).Hash -ne $manifest.diagnostic_template_sha256) { throw 'Diagnostic template changed.' }
$exe=Join-Path $root 'emule.exe'
$ini=Join-Path $root 'config\preferences.ini'
if($manifest.PSObject.Properties.Name -contains 'native_runtime_inputs') {
    foreach($record in $manifest.native_runtime_inputs) {
        if($record.name -ne [IO.Path]::GetFileName($record.name) -or !$record.name.EndsWith('.dll',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe native runtime input.' }
        $dll=Get-Item -LiteralPath (Join-Path $root $record.name)
        if($dll.Attributes -band [IO.FileAttributes]::ReparsePoint -or (Get-FileHash -LiteralPath $dll.FullName).Hash -ne $record.sha256) { throw 'Native runtime input changed.' }
    }
}
if((Get-FileHash -LiteralPath $exe).Hash -ne $manifest.executable_sha256 -or
   (Get-FileHash -LiteralPath $ini).Hash -ne $manifest.preferences_sha256) { throw 'Prepared input hashes changed.' }
$sections=@{}; $section=''
foreach($line in Get-Content -LiteralPath $ini) {
    if($line -match '^\[([^\]]+)\]$') { $section=$Matches[1]; if($sections.ContainsKey($section)) { throw 'Duplicate INI section.' }; $sections[$section]=@{} }
    elseif($line -match '^([^=]+)=(.*)$') {
        if(!$section -or $sections[$section].ContainsKey($Matches[1])) { throw 'Duplicate or unsectioned INI key.' }
        $sections[$section][$Matches[1]]=$Matches[2]
    }
}
$required=@{
    eMule=@{UsePublicUserDirectories='2';AutoConnect='0';AutoStart='0';AutoTakeED2KLinks='0';OpenPortsOnStartUp='0';BindAddr='127.0.0.1';RunAsUnprivilegedUser='0';
        IncomingDir=(Join-Path $root 'Incoming');TempDir=(Join-Path $root 'Temp')};
    Connection=@{IPv6Mode='0'};UPnP=@{EnableUPnP='0'};WebServer=@{Enabled='0'};
    eSE=@{EseNetLabEnabled='0'};KRPRelay=@{KrpRelayEnabled='0';KrpRelayKillSwitch='1';ExperimentalTcpDataPlane='0'}
}
if($diagnosticPort) { $required.WebServer=@{Enabled='1';Port=[string]$diagnosticPort;WebUseUPnP='0'} }
foreach($name in $required.Keys) {
    foreach($key in $required[$name].Keys) {
        if(!$sections.ContainsKey($name) -or $sections[$name][$key] -ne $required[$name][$key]) { throw "Unsafe profile setting [$name] $key" }
    }
}
if(!$sections.WebServer.Password) { throw 'Portable auto-enable must be prevented with a nonempty lab password.' }
if([int]$sections.eMule.Port -ne $manifest.tcp -or [int]$sections.eMule.UDPPort -ne $manifest.udp) { throw 'Port manifest mismatch.' }
# Availability check does not reserve the port for eMule; a race still fails the runtime test.
foreach($protocol in @('Tcp','Udp')) {
    $type=if($protocol -eq 'Tcp') { [Net.Sockets.SocketType]::Stream } else { [Net.Sockets.SocketType]::Dgram }
    $port=if($protocol -eq 'Tcp') { [int]$manifest.tcp } else { [int]$manifest.udp }
    $probe=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,$type,[Net.Sockets.ProtocolType]::$protocol)
    try { $probe.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$port)) }
    finally { $probe.Dispose() }
}
$arguments=@('--portable','--reach-binding-selftest','--ignoreinstances')
$started=[ordered]@{schema='ese.v93.reach-binding-started/1';started_utc=[DateTime]::UtcNow.ToString('o');
    executable_sha256=$manifest.executable_sha256;preferences_sha256=$manifest.preferences_sha256;arguments=$arguments;
    observation_timeout_seconds=$TimeoutSeconds}
[IO.File]::WriteAllText((Join-Path $root 'started.json'),($started|ConvertTo-Json -Depth 4),[Text.Encoding]::UTF8)
$process=Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru
# Retain the exact process handle before waiting: a PID can disappear or be
# reused. This is only an observation window, never a fixture deadline or kill.
$null=$process.Handle
[IO.File]::WriteAllText((Join-Path $root 'process-id.txt'),[string]$process.Id,[Text.Encoding]::UTF8)
$diagnosticSamples=0; $diagnosticFailures=0; $diagnosticWinner=$false; $diagnosticTerminal=$false
$diagnosticSequences=[Collections.Generic.HashSet[string]]::new()
if(!$diagnosticPort) { $terminal=$process.WaitForExit($TimeoutSeconds*1000) }
else {
    $handler=[Net.Http.HttpClientHandler]::new(); $handler.UseProxy=$false
    $http=[Net.Http.HttpClient]::new($handler); $http.Timeout=[TimeSpan]::FromSeconds(1)
    $until=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        do {
            $terminal=$process.WaitForExit(200)
            if($terminal) {break}
            $response=$null
            try { $response=$http.GetAsync("http://127.0.0.1:$diagnosticPort/api/reach/status").GetAwaiter().GetResult() }
            catch { continue } # startup/refused/shutdown is not a valid sample
            try {
                if([int]$response.StatusCode -ne 200 -or $response.Content.Headers.ContentType.MediaType -ne 'application/json' -or
                   !$response.Headers.CacheControl.NoStore -or !($response.Headers.GetValues('X-Content-Type-Options') -contains 'nosniff') -or
                   $response.Headers.ConnectionClose -ne $true) {throw 'Wrong diagnostic response headers'}
                $body=$response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $view=$body|ConvertFrom-Json
                if($view.schema_version -ne 2 -or $view.snapshot_sequence -isnot [string]) {throw 'Wrong diagnostic schema'}
                $values=@($view.snapshot_sequence)
                foreach($session in $view.sessions) {
                    foreach($field in @('snapshot_sequence','topology_generation','session_epoch','accepted_unique_bytes','fallback_count')) {
                        if($session.$field -isnot [string]) {throw 'Numeric uint64 diagnostic'}
                        $values+=$session.$field
                    }
                    if($session.session_id -notmatch '^d[1-9][0-9]*$' -or $session.PSObject.Properties.Name -contains 'endpoint' -or
                       $session.PSObject.Properties.Name -contains 'node' -or $session.candidate_summary.count -gt 16) {throw 'Unsafe diagnostic identity/candidate'}
                    if($session.auth_status -eq 'AUTHENTICATED' -and $session.state -in @('DIRECT','TRANSFERRING')) {$diagnosticWinner=$true}
                    if($session.state -in @('DIRECT_UNREACHABLE','CANCELLED')) {$diagnosticTerminal=$true}
                }
                foreach($value in $values) {
                    $parsed=[uint64]0
                    if($value -notmatch '^(0|[1-9][0-9]*)$' -or ![uint64]::TryParse($value,[ref]$parsed)) {throw 'Noncanonical uint64 diagnostic'}
                }
                [void]$diagnosticSequences.Add($view.snapshot_sequence); ++$diagnosticSamples
            } catch { ++$diagnosticFailures }
            finally { $response.Dispose() }
        } while([DateTime]::UtcNow -lt $until)
    } finally { $http.Dispose(); $handler.Dispose() }
}
$result=[ordered]@{schema='ese.v93.reach-binding-runtime/174';profile=$root;pid=$process.Id;terminal=$terminal;
    kad2_index_persistence_scope='V174 actual legacy CIndexed10000 sources normal Kad stop/write owned diagnostic profile real loader restart count10000 exact duplicate stable drain under30s; not GUI responsiveness 2h20 soak or exit20 diagnosis';
    classic_callback_feature_off_scope='V173 actual normal classic SmartID handling restored after feature disabled on owned second loopback server; no extra login or HighID';
    server_callback_fallback_scope='V172 real normal client login to two loopback classic protocol fixtures; one fallback duplicate LowID no third login old socket closed; no external server interoperability or HighID proof';
    diagnostic_scope='V162 actual Ready DCO projection shared GUI/API cache; V163 released terminal retained; no HTTP wire assertion';
    diagnostic_http=@{enabled=[bool]$diagnosticPort;samples=$diagnosticSamples;validation_failures=$diagnosticFailures;distinct_sequences=$diagnosticSequences.Count;authenticated_winner=$diagnosticWinner;retained_terminal=$diagnosticTerminal;scope='actual loopback HTTP if enabled; remote token/firewall and visible GUI not asserted'};
    both_control_idle_scope='V150 both original ledgers real65s idle fresh renewal remote fixture not second product';
    expired_control_scope='V149 real65s idle keepalive data then automatic recovery; simulated endpoints one host, not two product F1';
    automatic_quic_partial_recovery_scope='V148 automatic Transferring loss4096 written epoch1 preserved normal bootstrap AUTH epoch2 requests only gap1 actual hash complete4097; no F1 two products physical network expired control session';
    automatic_quic_recovered_file_scope='V147 automatic Ready loss QUIC epoch2 normal file negotiation real requests partial4096 IOCP duplicate suppression final actual hash complete4097 exact; no Transferring loss F1 two products physical network';
    control_recovery_sequence_scope='V146 active exact control session fresh verified higher sequence replay/context/digest rejection duplicate idle stability expired tombstone overflow alias safety; trusted ledger fixture no wire auth';
    automatic_quic_recovery_scope='V145 simulated public endpoint normal recovery pump fresh authenticated bootstrap selector native QUIC HELLOANSWER epoch2 same attempt source file credits lifetime token; no local manual routes file payload physical network two products';
    pinned_owned_recovery_scope='V144 actual QUIC loss retains prepared pin and bounded probe gate rejects changed trust context and stale handle; no positive public QUIC recovery or uTP consent';
    legacy_owned_recovery_scope='V143 actual TCP partial4096 socket loss retains recovery intent and unchanged epoch highwater useful bytes without eligible route; no positive public fallback';
    normal_dco_admission_scope='V142 normal capable download TryToConnect automatic admission BootstrapRequired once no classic cascade; no positive public route fallback';
    normal_connect_dco_fence_scope='V141 known capable normal TryToConnect live admitted DCO binding no parallel classic socket; no initial automatic admission public fallback';
    owned_utp_pending_close_scope='V140 actual pending uTP session closed twice before ACK detached owner cancel drains original preserved; no physical libutp drain proof';
    owned_utp_file_scope='V139 actual authenticated uTP requestparts partial4096 duplicate final byte IOCP real hash completed4097 disk exact; no F1 public fallback two products';
    owned_utp_bad_signature_scope='V138 actual uTP wire corrupt RSA signature IdentityMismatch once route drain original untouched; no file public fallback physical drain';
    owned_utp_identity_scope='V137 actual uTP wire capabilities challenge key signature fresh RSA DCO original adoption; no TCP observation useful bytes file proof public fallback';
    owned_utp_start_scope='V136 authorized DCO uTP Start shared UDP real connect HELLO exact IPv4 isolated client retirement; no SecureIdent file transfer physical drain proof';
    utp_peer_endpoint_scope='V135 actual accepted uTP exact full IPv4 short buffer required size unchanged null negative rejected; no authenticated DCO uTP transfer';
    legacy_reservation_failure_scope='V134 explicit consumer NoRoute after two reservations drains contexts and attempt terminal exactly once original client preserved; no automatic selector failure trigger';
    legacy_partial_reservation_scope='V133 two TCP reservations invalid third port zero creates no context owner retirement drains both late old handle rejected; no automatic registration failure branch or allocation injection';
    legacy_reservation_cancel_scope='V132 TCP reservation before Start cancelled by owner retirement drains context attempt subscription no socket original client ranges preserved; no injected allocation failure';
    legacy_start_ipv4_order_scope='V131 scheduled legacy temporary client network-order ConnectIP equals authorized route bytes before HELLO; loopback no public selector or uTP acceptance';
    observed_tcp_no_route_scope='V130 actual eligible partial file4096 gap1 no TCP route Unavailable preserves disk owner subscription recovery intent epoch highwater; no positive automatic fallback';
    observed_tcp_start_guard_scope='V129 actual admitted client without request file returns Unavailable no socket route highwater epoch subscription mutation; no eligible public positive start';
    tcp_consumer_availability_scope='V128 LAB consumer available without QUIC host or UDP socket disabled rejected; availability only not selected public route or TCP start';
    classic_standard_identity_scope='V127 TCP HELLOANSWER EMULEINFOANSWER key-and-signature challenge received before PUBLICKEY SIGNATURE fresh observation duplicate TTL stable; no two products public selector fallback';
    classic_tcp_identity_wire_scope='V126 extended real TCP HELLOANSWER PUBLICKEY EMULEINFOANSWER capability-triggered SECIDENTSTATE challenge received SIGNATURE duplicate parsed fresh RSA observation and rejection; key before capabilities loopback no public selector file fallback or two products';
    classic_tcp_observation_scope='V125 via V126 classic outbound real TCP identity wire fresh RSA observed TCP-only TTL duplicate stable missing mismatching own challenge corrupt signature rejected; loopback no public selector file fallback';
    mixed_file_recovery_scope='V124 QUIC partial4096 IOCP local close TCP route4 fresh RSA epoch2 original file gap1 wire request final real hash complete; explicit routes no physical loss uTP F1';
    legacy_packed_recovery_scope='V123 TCP compressed37 partial4096 real IOCP old inflater active close new route epoch2 decoder discarded disk kept gap1 requested plain final hash complete; no mixed uTP QUIC F1';
    legacy_route_recovery_scope='V122 TCP partial4096 actual close new route2 fresh RSA epoch2 original file request gap4096..4097 final hash completed exact; no mixed QUIC uTP race F1';
    legacy_request_scope='V121 TCP wire status slot production OP_REQUESTPARTS exact4097 no seeded reservation initial repair; explicit source file assignment no discovery mixed recovery F1';
    legacy_corruption_scope='V119 TCP corrupt final byte real hash rejects regaps4097 no integrity; V120 corrected4097 same authenticated socket new hash callback completed exact useful8194 seeded repair no route recovery F1';
    legacy_duplicate_scope='V118 TCP duplicate4096 actually parsed no useful byte receipt revision completion inflation; no overlapping ranges recovery F1';
    legacy_complete_file_scope='V117 real TCP final byte PartFile IOCP hash callback VerifiedPart completed4097 disk exact; seeded reservation no corruption recovery mixed race F1';
    legacy_partial_file_scope='V116 real TCP wire 4096 accepted PartFile provenance useful bytes IOCP disk exact no proof while final gap; seeded reservation no full hash recovery mixed race';
    mixed_host_selector_scope='V114 rejects advertised TCP without observed evidence changed identity mask zero id no socket before schedule; no positive public mixed selection';
    tcp_observation_scope='V115 actual adopted authenticated TCP exact endpoint lifetime hash topology expiry observation TCP only; mismatches expiry and UDP masks rejected no first contact gathering mixed transfer';
    legacy_physical_close_scope='V113 TCP peer close actual socket INVALID_SOCKET immediately wrapper deletion remains delayed; no uTP drain or cancellation timing acceptance';
    legacy_start_scope='V112 reserved TCP route DCO Start owns isolated socket creation actual Connect Hello real RSA original handoff close drain; harness replies direct parser calls no mixed race real file fallback or uTP/v6 runtime';
    legacy_original_handoff_scope='V111 separate TCP preauth client real RSA consumer original client adoption pending range preservation temporary retirement OS close recovery drain; no automatic Start mixed race or real file fallback';
    legacy_promotion_scope='V110 real RSA transcript commit to local pinned destination preserves counters challenges rejects changed signature challenge key invalid kind; temporary socket adoption rejected no original client handoff';
    legacy_route_credit_scope='V109 real TCP RSA verification private credits global record unchanged second same hash route challenge proof independent; no original client promotion or automatic race';
    legacy_consumer_scope='V108 prepared TCP consumer actual SecureIdent adoption OS close route drain subscriber retirement; no automatic Start mixed race or real file recovery';
    legacy_pending_scope='V107 actual adopted TCP peer close preserves seeded Pending_Block range start/end/transferred/totalUnzipped; no requested real PartFile range or recovered transfer';
    legacy_close_scope='V106 registered TCP route OS close bypasses classic client Disconnected, preserves lifetime/hash/credit pointer/requestfile/download state/subscription and detaches socket; no active pending range or recovery transfer test';
    legacy_adoption_scope='V105 real authenticated TCP socket exact coordinator winner epoch1 adopted once; wrong handle/route/epoch rejected, real peer close epoch1 seq3; explicit fixture caller not mixed consumer/file fallback';
    legacy_secureident_scope='V104 real ephemeral RSA signer, production public key/challenge/signature handlers and VerifyIdent; valid DCO winner epoch1 Attach, corrupt AuthFailed, duplicate ignored; direct handler calls not wire/adopted mixed transfer';
    legacy_valid_hello_scope='V103 direct matching HELLOANSWER through production parser after actual TCP connect, same client lifetime, DCO still Authenticating with no winner/useful/proof; SecureIdent/adoption and incoming merge pending';
    legacy_lifetime_scope='V102 late expected HELLO rejected by terminal route preflight; current lifetime/generation/epoch checks and classic merge bypass for registered owner implemented; incoming merge runtime coverage pending';
    legacy_wire_scope='V101 real loopback TCP send/OS receive/packet parser rejects changed HELLOANSWER hash, identity credit pointer handshake unchanged, exact AuthFailed without winner/proof; SecureIdent/adoption pending';
    legacy_packet_scope='V100 actual connected TCP route, direct production ProcessPacket HELLO rejection preserves hash/credit pointer/handshake and emits owned AuthenticationFailed; not wire input or SecureIdent';
    legacy_hello_scope='V99 direct production preflight calls: frozen expected hash, changed/truncated/null rejection, no auth claim; actual wire HELLO and SecureIdent adoption pending';
    legacy_endpoint_scope='V98 actual TCP loopback connection to a port different from authorized route: Closed IdentityMismatch before Connected, no winner/useful/proof; IPv6 and uTP runtime coverage pending';
    legacy_tcp_owner_scope='V97 actual loopback TCP listener and MFC socket; exact authorized route owner single registration, OS OnConnect and peer close emit owned Connected/Closed once, no authenticated winner/useful/proof. Explicit fixture socket cleanup and coordinator release; not mixed consumer retirement, SecureIdent, uTP owner or real file fallback';
    native_i64_scope='V96 valid native plain64 and continued packed64 reception with low offsets, exact4097 completed disk and real IOCP/hash; duplicate receipt unchanged. Harness source; not offsets above4GiB, REQUESTPARTS_I64 product generation, two products, F1 or full I64 acceptance';
    packed_native_malformed_scope='V95 native checksum error retains4096 valid bytes and gap1 without integrity proof; fully consumed late valid byte cannot revive errored reservation. Real remote OUTOFPARTREQS clears pending reservation without disconnect; FILESTATUS STARTUPLOADREQ ACCEPTUPLOADREQ lead to new REQUESTPARTS for only missing byte; real hash callback and completed disk exact4097 on same authenticated socket. Harness source; not full malformed corpus, I64, F1, two products or physical NAT';
    packed_malformed_scope='V94 production unzip direct lab rejects checksum mutation and a trailing byte after zlib end, returns zero output. Not malformed corpus exhaustiveness, native packet error lifecycle or full acceptance';
    all_packed_native_download_scope='V93 harness zstream SYNC_FLUSH first4096, delayed compressed final byte FINISH on same native session; product parser PartFile IOCP real hash exact4097 disk. All useful bytes compressed; additional plain duplicate gives no useful contribution. Not two products, malformed corpus, I64, F1 or physical NAT';
    packed_native_download_scope='V92 harness source compresses4096 bytes into37-byte packed32 application fragments; production native parser zstream PartFile useful4096 final gap, plain duplicate unchanged receipt, final plain byte real IOCP hash exact4097 disk. Not all-packed file completion, I64, F1, two products, physical NAT or full acceptance';
    packed_expansion_scope='V91 directly invokes production unzip under explicit lab access: seven-byte fragments reconstruct512; compressed2048 into reserved32 fails at33 probe and returns no output. Not full native packed reception, malformed corpus, IOCP hash or acceptance closure';
    packed_product_upload_scope='V90 real shared compressible disk file, normal slot request upload worker compression and throttler; bounded packed32 accumulation decompressed to 65537 exact bytes and MD4 at harness peer. Not native product download packed parsing, I64, F1, physical NAT or release acceptance';
    product_upload_scope='V89 actual shared file metadata/hash, remote slot and block requests, production upload queue disk worker and throttler over native stream; 65537 plain32 bytes exact and MD4 at harness receiver. Isolated loopback, not second product receiver, F1, bidirectional, NAT, fallback or restart';
    observation_timeout_seconds=$TimeoutSeconds;observation_expired=(!$terminal);process_handle_captured=$true;
    observation_scope='Only waits for the launched process; does not change fixture deadlines, kill a live process, infer exit from PID absence or accept a partial log';
    multipart_native_scope='V88 continuous production discovery source and requested file through native handshake; PARTSIZE plus 4097 bytes, two real MD4 part hashes/eD2K root, requested FILESTATUS/HASHSETANSWER/slot/block ranges, bounded 32768-byte plain32 chunks, real hash workers and exact completed disk. Memory network and explicit signed witness, harness peer uploader; not physical NAT, 1GiB F1 dataset, fallback, restart, compression, I64, simultaneous files or full A1';
    integrated_native_scope='V87 signed explicit witness cookie PROVE ACK0 automatic FIND SOURCES GET RESULT; production queue Process consumes manager mailbox into cold source; elapsed Windows timer starts native caller with durable known pin, signed ACK4 and native AUTH HELLO file IOCP hash completion; corrupt part reask blocked before deadline and by banned upload state; seeded expired per-file timestamp then real timer requests same authenticated socket, real block requests repair exact disk and hash. Discovery and peer transfer driven by harness, repair source membership supplied explicitly; memory datagrams single part 4097 bytes, not full autonomous queue lifecycle, physical NAT, seed discovery, multipart, real elapsed 58min, general ban policy or release';
    profile_trust_scope='V74 manager uses isolated actual eMule config/peer_trust profile, unknown key rejects implicit TOFU, explicit choice configures atomic commit, real disk before HELLO and reconnect configuration loads known pin; not application restart, second handshake, rotation UI or automatic scheduler';
    first_use_scope='V73 explicit cold first-use fixture with no pin, manager host/consumer require durable committer, real TOFU disk before production HELLO, HELLOANSWER and same requested real PartFile 4097 byte hash completion; not product profile selection, stable reference UI or automatic discovery scheduler';
    pending_server_scope='V72 explicit pinned local subscriber authorization, wrong pin and duplicate reject; real cookie/signed PROVE from loopback is rejected by public route policy, signed ACK0, no new attempt/route or lease renewal; fixture restores control ledger before independent V71, not positive public endpoint preparation';
    prepared_server_scope='V71 explicit lab server route and pinned identity, actual shared UDP cookie PROVE signed selected4 ACK, then peer QUIC client and production HELLOANSWER; not automatic product consent, cold discovery scheduler or file transfer';
    cold_file_scope='V70 native-only initially unidentified signed source with same requested real PartFile across authenticated QUIC and HELLOANSWER, 4097 bytes IOCP write, real hash worker completion and exact disk; explicit fixture authorization and scheduled loopback route, not learned discovery scheduler or automatic consent';
    cold_rejection_scope='V69 native-only cold explicitly authorized fixture: changed hash/node, missing/duplicate node, truncated HELLOANSWER and SENDINGPART before HELLO reject with no installed identity/hash/credits; terminal IdentityMismatch single use, unread terminal protected and drained owner; no product consent negotiation';
    cold_hello_scope='V68 native-only signed descriptor/source on initially unidentified fixture client, explicitly authorized attempt and scheduled loopback route, actual QUIC binding then lifetime attach and real HELLOANSWER; no identity/hash/credits before answer, no product consent negotiation, learned discovery-to-transport scheduler or file transfer';
    learned_cold_source_scope='V67 native-only signed CLOSER learned witness actual bootstrap FIND SOURCES GET and shared manager reply consumed by real Process to create one previously absent cold source of queued file; corrupt RESULT creates none, duplicate keeps pointer/lease/count, no HELLO/hash/credits/endpoint/socket/DCO slot; first witness trusted, no cold transport or transfer';
    cold_source_scope='V66 native-only production queue creates real clients for signed known-file descriptors with expected node separate from HELLO/userhash/credits; corrupt signatures/size reject, same node duplicate no lease renewal, two nodes same claimed hash do not merge, Process/TryToConnect/RequestNative do not invent sockets/slots/consent; direct fixture supplies signed candidates, no learned-manager cold receipt or cold transport';
    learned_queue_delivery_scope='V65 native-only signed CLOSER learned witness real bootstrap FIND SOURCES GET, corrupt RESULT then valid shared manager ingress consumed by actual DownloadQueue Process into explicit existing peer of real queued file; signed advertised route, duplicate no lease/credit renewal, resolution cancel preserves consumed snapshot; no cold source or transport start';
    discovery_queue_scope='V64 native-only real queued CPartFile and explicit existing source, wrong file/size/node rejection, queue adopts signed descriptor into same client without credit mutation; does not prove manager delivery, automatic Process consumption, cold source creation or transport';
    discovery_client_scope='V63 native-only CUpDownClient with real requested CPartFile adopts signed source/descriptor into owned snapshot, rejects wrong file/topology/expired, caps TTL, detach retires, hash/credits unchanged; fixture supplies identity and evidence, no DownloadQueue discovery or transport start';
    resolution_learned_candidate_scope='V62 native-only CLOSER learned W real bootstrap then automatic FIND/SOURCES/GET in same authenticated session, corrupt RESULT rejection/exact candidate once; initial W trusted, descriptor no routes, no PartFile/IPv6';
    resolution_learned_bootstrap_scope='V61 native-only signed CLOSER learned loopback endpoint, automatic cookie/HMAC/PROVE/signed ACK exchange; corrupt first ACK then retry/single peer adoption and automatic session-bound FIND; initial W trusted, no learned source/PartFile or IPv6';
    resolution_closer_scope='V60 native-only signed CLOSER learned into cache/probation, corrupt outer rejected, no FIND for 100ms/no session promotion; trusted return then explicit AddWitness permits automatic FIND, capability bit fixed; no automatic bootstrap';
    resolution_alternate_scope='V59 native-only shared manager two signed witnesses with trusted preadmitted sessions, automatic FIND/SOURCES/GET; first owner expires, second GET and candidate once, late first no candidate; no dual bootstrap/CLOSER/PartFile';
    resolution_get_retry_scope='V58 native-only unanswered first GET then original signed retransmission/backoff, same owner corrupt/valid RESULT/candidate once; no alternate witness, second GET retry/deadline fixture or PartFile';
    resolution_find_retry_scope='V57 native-only unanswered first FIND then byte-exact signed retry after backoff, automatic GET/candidate; no second retry/deadline loss fixture or GET retry/PartFile';
    resolution_auto_find_scope='V56 native-only explicit enable with validated witness and live bootstrap session: manager selects/signs/sends FIND, automatic GET and verified candidate; no CLOSER probation, retries or PartFile';
    resolution_auto_get_scope='V55 native-only explicit per-resolution enable automatically reserves/signs/sends GET after verified SOURCES; corrupt/valid RESULT, candidate once, no duplicate UDP for 100ms ticks; no retry or automatic FIND/PartFile';
    resolution_sequence_scope='V54 native-only manager reserves GET sequence greater than explicit FIND with exact live bootstrap attempt/generation, signs exact UDP request; no scheduler or session TTL renewal credited';
    resolution_owned_get_scope='V53 native-only manager builds/local persistent-signs GET from located source, invalid index rejected, exact UDP request then verified candidate; caller still supplies request header/slot/index';
    resolution_locator_scope='V52 native-only manager snapshot of verified received source supplies file/size/W/endpoint/locator/remaining TTL for GET; no automatic product scheduler or PartFile adoption';
    resolution_rejection_scope='V51 native-only corrupt SOURCES/RESULT processed by shared manager rejection counter, no GET/candidate, subsequent valid replies complete same pending owners; not session revocation or inner descriptor tampering';
    resolution_candidate_scope='V50 native-only real bootstrap session/shared MFC manager signed SOURCES, persistent DESC_GET exact UDP, signed RESULT and owned candidate single delivery; loopback lab witness/publisher, no PartFile adoption or automatic discovery';
    resolution_find_scope='V49 native-only manager fresh signed witness with lab caps1/live bootstrap, round selection, persistent signed FIND shared UDP exact peer receive and cancel invalid owner; no SOURCES or DESC_GET manager receipt';
    resolution_lifecycle_scope='V48 native-only manager resolution start/invalid size/duplicate, disable pump cancellation, reenable and explicit cancel new operation; no FIND/GET manager ingress or deadline/topology change fixture';
    bootstrap_disable_scope='V47 native-only disable before first pump, zero UDP packets observed for 350ms, no Ready/new admission, reenable fresh owner; not disable after authenticated ACK';
    responder_recovery_scope='V46 native-only second authorized real UDP port fresh CSPRNG attempt/nonce, own challenge and signed proof/ACK, new live manager session with original preserved; no physical NAT or automatic endpoint migration';
    responder_rebind_scope='V45 native-only second real UDP source port separately authorized for same key, original signed proof processed/rejected without session at either endpoint, original source completes; no physical NAT or fresh challenge on rebound endpoint credited';
    responder_cookie_scope='V44 native-only mutated PROVE cookie re-signed with real peer key and signature verified locally; manager processes/rejects without session, original proof completes; not source-port rebinding';
    control_responder_scope='V43 native-only authorized ephemeral loopback initiator/production MFC responder, challenge cookie, corrupt PROVE manager rejection/no session, valid admission and persistent signed ACK, duplicate byte-exact ACK; no discovery policy or route grant';
    bootstrap_deadline_scope='V42 native-only first CHALLENGE dropped, 2 PROBE/3 identical PROVE, 3 corrupt ACK manager rejections, peer one adoption/two duplicates; deadline no live session or cache mutation, fresh owner admission; loopback lab responder';
    bootstrap_retry_scope='V41 native-only corrupt first ACK processed by manager with no Ready, one byte-exact PROVE retransmission, peer Duplicate and one adoption, valid ACK completes; not loss of CHALLENGE or all-ACK deadline';
    control_bootstrap_scope='V40 native-only real shared UDP four-message bootstrap, persistent requester/CSPRNG attempt+nonce, peer cookie/HMAC/PROVE verification, signed ACK manager session then contact refresh; loopback ephemeral responder, no discovery policy or route grant';
    contact_revocation_scope='V39 native-only pending refresh after real corrupt reply; session cleared, production pump called, trusted session restored before deadline; same owner send invalid and cache unchanged; no late-datagram delivery or bootstrap credited';
    contact_rejection_scope='V38 native-only corrupt RESULT reaches manager rejection counter, cached epoch unchanged, subsequent valid RESULT completes same pending owner; not session revocation or bootstrap';
    contact_refresh_scope='V37 native-only signed GET and RESULT over actual shared MFC UDP, pending owner and production cache epoch update, completed owner single use; trusted control-session admission fixture, not bootstrap or physical discovery';
    native_admission_scope='V34 client-owned Created/Joined admission; no live reset/terminal, no unread terminal overwrite, exact lifetime and single-use IdentityMismatch, fresh token/generation only after consumed released attempt; not automatic retry or TryToConnect new-session admission';
    native_reuse_scope='V33 real TryToConnect already-connected branch before/after HELLO preserves same socket and DCO attempt/winner/epoch; not new-session admission, TCP/uTP/QUIC selection or legacy interoperability';
    native_duplicate_scope='V32 duplicate partial SENDINGPART fully consumed by production native receiver, useful bytes and owned receipt revisions unchanged in valid/corrupt-repair fixtures; not overlapping ranges or general duplicate statistics';
    native_corruption_scope='V30 wrong final byte regaps single part without proof/completion; V31 correct same-session retry requires a new real hash callback, VerifiedPart and completed disk exact; useful total8194 includes rejected and repaired writes; not multipart corruption acceptance';
    native_file_scope='V27/V28 partial file: 4096 useful bytes and exact IOCP disk writes, final gap and no integrity proof; V29 final byte: real hash worker and window callback, manager VerifiedPart, completed file 4097 bytes exact; only loopback single-part fixture, not general download acceptance';
    block_header_scope='V26 requires 116 direct production parser rejections of short/empty/null plain32/plain64/packed32/packed64 headers before offset reads; not valid file block reception or disk writes';
    utp_accept_scope='V35 generated libutp SYN over real loopback UDP/shared MFC socket; nearby-port rejection, exact ownerless accept without HELLO identity and wrapper retirement; not authenticated DCO uTP transfer or physical NAT rebind';
    utp_owner_scope='V36 real UDP SYN with injected mismatching nonzero expectation owner generation is not adopted; unregister removes freshly seeded owner expectation; callbacks counted only for current peer socket; not actual allocator address reuse, DCO identity or physical rebind';
    native_identity_scope='native profiles require V24 changed hash and V25 changed/missing/duplicate node and truncated HELLOANSWER: no legacy identity mutation, typed IdentityMismatch and resource drain; not malformed-tag exhaustiveness or incoming OP_HELLO variants';
    executable_sha256=$manifest.executable_sha256;observed_exit_code=$null;verdict='RUNNING';log_sha256=$null;
    acceptance_scope='loopback bindings, mailbox, injected topology/resume, host CSPRNG/shared admission, subscriber retirement, real file lifetimes, disk hash worker/message delivery, stale verdict fencing and fixture digest acceptance; native profiles additionally shared UDP lifecycle, persistent identity, authenticated peers/DCO, bidirectional transport, signature and HELLO identity rejection, manager consumer/parser and single-part PartFile write/hash/completion as detailed by native_file_scope; not normal TryToConnect, multipart/corrupt native file acceptance, physical sleep/router or full A1'}
if($terminal) {
    $result.observed_exit_code=$process.ExitCode
    $log=Join-Path $root 'logs\eMule.log'
    $result.verdict='FAIL'
    if(Test-Path -LiteralPath $log) {
        $result.log_sha256=(Get-FileHash -LiteralPath $log).Hash
        $logText=Get-Content -LiteralPath $log -Raw
        $hasNativeSnapshotMarker=$logText.Contains('REACH_SELFTEST V6 PASS: real client native endpoints, byte order and no invented route proof')
        $hasConsumerMarker=$logText.Contains('REACH_SELFTEST V7 PASS: installed QUIC consumer without implicit host activation')
        $hasConsumerMarker=$hasConsumerMarker -and $logText.Contains('REACH_SELFTEST V128 PASS: LAB consumer TCP availability without QUIC host or UDP socket; disabled rejected; availability only no route start')
        $hasOwnedScheduleMarker=$logText.Contains('REACH_SELFTEST V8 PASS: owned QUIC scheduling, endpoint fence, terminal sink and failed-start drain')
        $hasPartLifetimeMarker=$logText.Contains('REACH_SELFTEST V9 PASS: real part-file lifetimes and owned keys, no file hash acceptance')
        $hasDigestMarker=$logText.Contains('REACH_SELFTEST V10 PASS: production MD4 known vector and changed payload, not disk/hash-job acceptance')
        $hasDiskHashMarker=$logText.Contains('REACH_SELFTEST V11 PASS: production disk hash job, identity and truncated range rejection, not async callback acceptance')
        $hasWorkerMarker=$logText.Contains('REACH_SELFTEST V12 PASS: real hash worker queue and window-message delivery, not PartFile verdict acceptance')
        $hasVerdictFenceMarker=$logText.Contains('REACH_SELFTEST V13 PASS: PartFile stale verdict preserves pending job and snapshot, no valid hash acceptance')
        $hasHashGenerationMarker=$logText.Contains('REACH_SELFTEST V14 PASS: part hash generation saturates without reuse')
        $hasAcceptanceMarker=$logText.Contains('REACH_SELFTEST V15 PASS: PartFile accepts disk digest and rejects changed digest, fixture pending marker prevents completion')
        $hasNativeHostMarker=$true
        $hasBlockHeaderMarker=$logText.Contains('REACH_SELFTEST V26 PASS: block parser rejects truncated empty and null headers for packed plain and I64 before offset reads')
        if(($manifest.PSObject.Properties.Name -contains 'native_runtime_inputs') -and @($manifest.native_runtime_inputs).Count -gt 0) {
            $hasNativeHostMarker=$logText.Contains('REACH_SELFTEST V16 PASS: native shared UDP host attach, exclusive ingress, detach and reattach, no sessions') -and $logText.Contains('REACH_SELFTEST V17 PASS: invalid native session admission leaves shared socket bound and host empty') -and $logText.Contains('REACH_SELFTEST V18 PASS: real MFC shared UDP authenticated peer, DCO winners, bidirectional 4096 bytes and drained resources') -and $logText.Contains('REACH_SELFTEST V20 PASS: received native bytes disk MD4, owned session receipt and single-use DCO VerifiedPart, not PartFile consumer')
        }
        if(($manifest.PSObject.Properties.Name -contains 'native_runtime_inputs') -and @($manifest.native_runtime_inputs).Count -gt 0) {
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V19 PASS: real MFC shared UDP rejects peer bad signature, typed DCO failure, zero useful bytes and drained resources') -and $logText.Contains('REACH_SELFTEST V22 PASS: manager QUIC consumer authenticated client attachment, real outgoing HELLO, logical peer address and subscriber retirement, no incoming PartFile')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V23 PASS: peer serialized HELLOANSWER through native consumer and production parser, handshake finished, bound identity and endpoint preserved, zero file progress')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V24 PASS: native consumer rejects changed HELLO hash before legacy identity mutation, terminal IdentityMismatch and drained resources')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V25 PASS: changed missing duplicate node and truncated HELLO rejected before legacy mutation, terminal IdentityMismatch and drained resources')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V27 PASS: native SENDINGPART production parser accepts 4096 bytes into real PartFile, final gap remains, useful progress without integrity proof')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V28 PASS: native PartFile production IOCP writes drained and 4096 disk bytes exact, final gap and no integrity proof')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V29 PASS: native final byte production hash callback manager VerifiedPart and completed file 4097 bytes exact')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V30 PASS: native corrupt file production hash callback regaps all 4097 bytes, no VerifiedPart or completion, useful bytes remain transport progress')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V31 PASS: native corrupt file repaired on same session with new real hash callback, VerifiedPart, completed disk exact and 8194 useful bytes')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V32 PASS: native duplicate SENDINGPART fully consumed without useful byte inflation or receipt mutation, valid and repair flows preserved')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V33 PASS: real TryToConnect reuses adopted native socket before and after HELLO without new attempt winner epoch or file progress')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V34 PASS: client owned admission joins same token, typed single-use terminal blocks unread retry, consumed drained retry uses fresh token generation')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V37 PASS: signed contact GET and RESULT over real shared UDP, manager cache epoch update and single-use owner; trusted session fixture, not bootstrap')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V38 PASS: corrupt signed contact RESULT processed and rejected by manager, cache unchanged, valid reply still completes same owner')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V39 PASS: pending contact owner retired by manager pump on session revocation before deadline, restored session cannot resurrect owner, cache unchanged')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V40 PASS: real shared UDP PROBE CHALLENGE persistent-signed PROVE and peer-signed ACK, manager control session authorizes contact refresh')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V41 PASS: corrupt bootstrap ACK rejected without Ready, byte-exact PROVE retry, peer duplicate with one adoption, valid ACK completes')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V42 PASS: lost first CHALLENGE and three corrupt ACKs, bounded PROBE and PROVE retries, deadline no session or cache mutation, fresh owner allowed')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V43 PASS: production shared UDP responder challenge, corrupt PROVE rejected without session, valid PROVE admission and persistent ACK, duplicate exact ACK')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V44 PASS: correctly re-signed PROVE with changed cookie rejected by production responder without session, original PROVE still admitted')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V45 PASS: valid signed PROVE cookie reused from separately authorized second UDP port rejected without session, original endpoint completes')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V46 PASS: second UDP port fresh CSPRNG attempt and nonce, new challenge and signed PROVE ACK establish rebound session without changing original session')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V47 PASS: disabled pending initiator sends zero UDP packets for 350ms, rejects new bootstrap, reenable allocates fresh owner')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V48 PASS: manager resolution invalid size and duplicate rejected, disable pump cancels, reenable and explicit cancel permit fresh operation')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V49 PASS: manager selects fresh signed witness with live bootstrap session, sends persistent signed FIND over shared UDP byte-exact, cancel invalidates owner')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V50 PASS: shared manager signed SOURCES then persistent DESC_GET and signed RESULT produce exact owned candidate delivered once')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V51 PASS: shared manager rejects corrupt SOURCES without GET and corrupt RESULT without candidate, valid replies complete original owners')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V52 PASS: shared manager located-source snapshot supplies verified file size witness endpoint locator and remaining TTL for signed GET')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V53 PASS: manager builds and persistent-signs GET from located source, invalid index rejected, exact peer UDP request produces verified candidate')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V54 PASS: manager reserves GET sequence after FIND in exact bootstrap attempt generation and signs exact shared UDP request')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V55 PASS: shared manager automatically reserves signs sends GET after SOURCES, verifies candidate, repeated ticks send no duplicate')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V56 PASS: shared manager selects witness reserves signs sends FIND then automatic GET and verified candidate')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V57 PASS: unanswered first FIND retransmitted signed byte-exact after backoff, automatic GET delivers verified candidate')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V58 PASS: unanswered first GET retransmitted signed byte-exact after backoff, same owner verifies candidate once')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V59 PASS: shared manager first witness expires then automatically GETs second witness, late first reply grants no candidate, second delivers once')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V60 PASS: corrupt CLOSER not imported, signed learned contact remains probation with no FIND until live return promotion')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V61 PASS: signed CLOSER learned witness real cookie bootstrap rejects bad ACK, retries and automatically promotes signed FIND in exact session')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V62 PASS: learned witness real bootstrap FIND SOURCES automatic signed GET rejects corrupt RESULT and delivers exact candidate once')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V63 PASS: real requested file client owns signed discovery snapshot, topology and detach fence, no hash or credit mutation')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V64 PASS: DownloadQueue exact requested file and size, existing node peer only, signed client snapshot and credit identity unchanged')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V65 PASS: learned witness bootstrap FIND SOURCES GET shared manager ingress and DownloadQueue Process adopts signed route once, duplicate no lease or credit renewal')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V66 PASS: signed Kad6 creates node-only requested-file sources, duplicate no lease renewal, distinct nodes never merge by claimed hash, no HELLO credits socket consent or slot invented')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V67 PASS: learned witness real bootstrap FIND SOURCES GET shared ingress and Process creates exactly one cold requested-file source, corrupt and duplicate grant no identity credits socket or slot')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V68 PASS: initially unidentified signed source attaches by lifetime to authenticated QUIC then real HELLOANSWER establishes bound identity, explicit fixture authorization only, zero file progress')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V69 PASS: cold changed hash or node, missing duplicate or truncated node and pre-HELLO data reject before identity or credits, typed terminal single use and owner drain')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V70 PASS: initially unidentified signed source authenticates QUIC and HELLO then same requested PartFile receives 4097 bytes, real IOCP hash completion and exact disk, explicit fixture authorization and route')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V71 PASS: explicit prepared server route authorizes real UDP cookie PROVE signed selected4 ACK then peer QUIC client and production HELLOANSWER, no automatic consent')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V72 PASS: pending pinned subscriber authorization rejects wrong pin and duplicate, real UDP PROVE loopback policy yields signed ACK0 without new attempt route or lease renewal')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V73 PASS: cold source without pin through manager host consumer persists TOFU before production HELLO then HELLOANSWER and 4097 byte real PartFile hash completion, explicit first-use fixture')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V74 PASS: manager profile unknown key rejects implicit first-use, explicit TOFU persists before HELLO and reconnect configuration reloads known pin without new committer')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V75 PASS: simulated namespace signed cookie PROVE ACK4 triggers manager owned handoff without manual route schedule then native AUTH TOFU production HELLO HELLOANSWER; no physical UDP NAT or AskForDownload scheduler')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V76 PASS: same authenticated peer durable pin second handshake AskForDownload creates single-flight admission then signed ACK4 owned handoff AUTH HELLO HELLOANSWER without explicit BeginOwned or new TOFU; simulated namespace no physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V77 PASS: AskForDownload known-pin signed source through ACK4 native AUTH HELLO then same requested PartFile 4097 exact bytes IOCP disk duplicate suppression real hash and completion; simulated namespace single part no physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V78 PASS: production filename answer ACCEPTUPLOADREQ generates exact signed-file OP_REQUESTPARTS and real pending blocks then 4097 byte hash completion over automatic caller QUIC; no manual ReserveDownload simulated single part')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V79 PASS: owned negotiation enters DS_CONNECTING then HELLOANSWER triggers real filename request signed file ID upload request and requested slot before automatic blocks; no unsolicited file status simulated single part')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V80 PASS: AskForDownload survives dropped first challenge and ACK with two PROBEs two byte-identical PROVEs single admission no premature route then automatic file hash completion; simulated loss not physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V81 PASS: two additional native QUIC datagrams lost during first file block recover exact bytes without new attempt winner epoch or subscriber then duplicate suppression disk hash completion; simulated packet loss not disconnected transport')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V82 PASS: automatic QUIC corrupt final byte fails real hash regaps no completion then AskForDownload same socket filename slot real block requests repair exact disk bytes and verified completion; simulated single part no manual repair reservation')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V83 PASS: PartFile periodic source processing while classic network disconnected invokes native caller creates one attempt repeated tick preserves subscriber then signed ACK QUIC automatic file completion; fixture source membership no full queue timer')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V84 PASS: actual DownloadQueue Process ten-tick cycles dispatch registered PartFile native caller offline second cycle single-flight then automatic QUIC file completion; explicit fixture source insertion no elapsed real timer')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V85 PASS: production queue rejects corrupted signed discovery creates cold source from valid evidence duplicate preserves lifetime then queue native caller automatic QUIC requests disk hash completion and corrupt repair; resolved candidate fixture not network FIND GET')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V86 PASS: signed explicit witness real cookie PROVE ACK0 automatic signed FIND SOURCES GET RESULT manager owned candidate then production queue source QUIC ACK4 AUTH requests disk hash completion; memory datagrams no physical NAT seed discovery')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V87 PASS: production discovery mailbox queue Process source then elapsed Windows timer native caller ACK4 AUTH HELLO file hash corruption repair; repair cooldown and banned state prevent reask then seeded expired timestamp timer requests same socket blocks exact disk hash; memory single part explicit witness no physical NAT multipart')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V88 PASS: continuous discovered source and requested file through native AUTH HELLO then multipart PARTSIZE plus 4097 real status hashset slot block requests bounded chunks two hash callbacks and exact disk completion; memory explicit witness no physical NAT F1 fallback restart')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V89 PASS: authenticated native peer requests real shared file normal upload slot disk worker throttler plain32 packets 65537 exact bytes and MD4; loopback harness receiver no physical NAT F1 bidirectional fallback restart')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V90 PASS: normal shared file upload disk worker compression throttler native stream bounded packed32 reconstruction 65537 exact bytes and MD4; harness receiver not product download F1 I64 or physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V91 PASS: production unzip seven-byte input fragments exact512 and reserved32 rejects expansion2048 at probe33 with no returned output; direct decoder lab not native file acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V92 PASS: authenticated native compressed37-byte fragments production PartFile4096 useful final gap duplicate plain no new receipt then final plain byte IOCP real hash and exact4097 disk; harness source not F1 I64 or physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V93 PASS: authenticated native all useful file bytes compressed same zstream sync flush4096 final gap then compressed final byte stream end IOCP real hash exact4097 disk; plain duplicate no useful credit harness source not F1 I64 physical NAT')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V94 PASS: production unzip altered checksum and trailing byte after zlib end reject with zero returned output; direct decoder lab not full malformed native corpus')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V95 PASS: native packed checksum error retains4096 gap1 rejects late byte; remote release clears reservation normal slot requests missing byte real hash completes exact4097 same authenticated socket; harness source not full malformed corpus')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V96 PASS: native plain64 and continued packed64 exact4097 IOCP hash completion duplicate receipt stable; harness source low offsets not above4GiB or request64 acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V97 PASS: real loopback TCP socket exact route owner Connected then Closed once no auth winner useful proof; explicit fixture cleanup not mixed consumer fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V98 PASS: real TCP wrong destination rejected before Connected authentication winner useful bytes or proof')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V99 PASS: legacy HELLO frozen expected hash preflight rejects changed truncated null input no authentication; direct preflight calls not wire SecureIdent acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V100 PASS: connected TCP owned HELLO packet rejection preserves hash credits handshake emits exact AuthenticationFailed no winner proof; direct packet call not wire SecureIdent')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V101 PASS: actual TCP wire HELLOANSWER changed hash reaches receive parser rejects before identity credits handshake mutation owned AuthFailed no winner proof; no SecureIdent adoption')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V102 PASS: terminal TCP route rejects late matching HELLO preflight; legacy owner merge guard implemented not incoming merge runtime acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V103 PASS: matching HELLOANSWER production parser preserves TCP owner lifetime no DCO authentication winner useful proof; direct packet call no SecureIdent adoption')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V104 PASS: actual RSA SecureIdent valid winner epoch1 Attach corrupt IdentityMismatch no winner duplicate no event; direct signature handler not wire adoption mixed transfer')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V105 PASS: authenticated TCP exact winner adoption once rejects stale handle route epoch real peer close carries epoch1; explicit fixture adoption not mixed consumer or file recovery')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V106 PASS: owned TCP peer close preserves client lifetime hash credit requestfile download state subscription detaches socket; no active range or file recovery acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V107 PASS: adopted TCP real peer close preserves seeded pending block offsets transferred unzipped accounting; no real file range recovery acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V108 PASS: prepared TCP consumer owns real SecureIdent Attach OS close common drain and subscriber retirement preserves pending range; no automatic Start mixed race or real file recovery')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V109 PASS: real TCP route SecureIdent uses private credits global record unchanged second same hash route challenge proof independent; no original client promotion or automatic race')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V110 PASS: route RSA transcript promotion rejects changed signature challenge pinned key invalid kind preserves destination counters challenges; isolated socket cannot adopt no original client handoff yet')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V111 PASS: separate preauth TCP client RSA consumer adopts original transfer client preserves seeded pending range retires temporary client OS close recovery drain; no automatic Start race or real file fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V112 PASS: reserved TCP route DCO Start consumer creates connects isolated socket Hello real RSA original handoff range preservation close drain; no mixed race or real file fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V113 PASS: adopted TCP close releases actual OS socket immediately while delayed wrapper retains late callback safety; no uTP physical drain or cancellation timing acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V114 PASS: host owned TCP snapshot rejects advertised unobserved endpoint changed hash unknown mask zero id no socket starts QUIC wrapper preserved; no positive public mixed selection or transfer')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V115 PASS: actual authenticated adopted TCP records exact endpoint lifetime hash topology expiry proof TCP only rejects mismatched port hash generation lifetime stale and UDP masks; no first contact gathering or mixed file fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V116 PASS: real TCP wire 4096 accepted PartFile legacy provenance useful bytes exact IOCP disk no integrity while final gap; seeded reservation no full hash recovery mixed race')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V117 PASS: real TCP final byte PartFile IOCP hash worker callback VerifiedPart and completed4097 disk exact; seeded reservation no corruption recovery mixed race F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V118 PASS: TCP duplicate4096 actually parsed no useful byte receipt revision or completion inflation; no overlapping ranges recovery F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V119 PASS: TCP corrupt final byte real hash rejection regaps4097 no VerifiedPart or completion; no F1 mixed recovery')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V120 PASS: TCP corrected4097 same authenticated socket new real hash callback VerifiedPart completed disk exact useful8194; seeded repair reservation no route recovery F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V121 PASS: TCP wire FILESTATUS and ACCEPTUPLOADREQ production creates OP_REQUESTPARTS exact4097 no seeded block reservation initial and repair; explicit source file assignment no discovery mixed recovery F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V122 PASS: TCP partial4096 actual close new route2 fresh RSA adopted epoch2 original PartFile retained request only4096..4097 final real hash completed exact; no mixed QUIC uTP race F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V123 PASS: TCP compressed37 fragments4096 real IOCP partial old inflater active close fresh route epoch2 discards decoder keeps disk requests gap1 plain final hash complete exact; no uTP QUIC mixed F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V124 PASS: QUIC partial4096 IOCP local transport close TCP route4 fresh RSA epoch2 original file gap1 wire request final real hash completed exact; explicit routes no physical loss uTP F1')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V130 PASS: actual resumable partial4096 gap1 without eligible TCP route returns Unavailable preserves disk owner subscription recovery intent epoch highwater; no positive automatic fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V125 PASS: classic outbound real TCP fresh RSA observation TCP-only TTL duplicate stable missing and mismatching own challenge corrupt signature rejected; handlers loopback no public selector file fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V126 PASS: classic TCP wire HELLOANSWER PUBLICKEY SIGNATURE and duplicate actually parsed fresh RSA observation or rejection; loopback no public selector file fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V127 PASS: classic TCP capabilities trigger key-and-signature challenge received before peer key then fresh signature observation duplicate TTL stable; loopback no two products public selector fallback')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V129 PASS: observed TCP start without request file returns Unavailable preserves subscription attempt epoch route highwater and creates no socket; no eligible public positive start')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V131 PASS: scheduled legacy temporary client ConnectIP matches authorized IPv4 bytes before HELLO; loopback not public selector or uTP acceptance')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V132 PASS: reserved legacy TCP cancellation before Start drains context attempt subscription no socket preserves original client ranges; no injected allocation failure')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V133 PASS: two TCP reservations invalid third creates no context owner retirement drains both late old handle rejected; no automatic registration failure branch or allocation injection')
            $hasNativeHostMarker=$hasNativeHostMarker -and $logText.Contains('REACH_SELFTEST V134 PASS: explicit consumer NoRoute failure drains two unscheduled TCP reservations terminal exactly once original client preserved; no automatic selector failure trigger')
        }
        if($process.ExitCode -eq 0 -and $logText.Contains('REACH_SELFTEST PASS: real bindings, generation fence, single-use, UDP disable and TCP close') -and $logText.Contains('REACH_SELFTEST V2 PASS: signature invalidation and WM_POWERBROADCAST resume handler') -and $logText.Contains('REACH_SELFTEST V3 PASS: host CSPRNG admission and shared native attempt') -and $logText.Contains('REACH_SELFTEST V4 PASS: owned subscriber binding, peer fence and single-use retirement') -and $logText.Contains('REACH_SELFTEST V5 PASS: real client lifetime destructor and deferred retirement') -and !$logText.Contains('REACH_SELFTEST FAIL')) { $result.verdict='PASS' }
        if(!$hasNativeSnapshotMarker -or !$hasConsumerMarker -or !$hasOwnedScheduleMarker -or !$hasPartLifetimeMarker -or !$hasDigestMarker -or !$hasDiskHashMarker -or !$hasWorkerMarker -or !$hasVerdictFenceMarker -or !$hasHashGenerationMarker -or !$hasAcceptanceMarker -or !$hasNativeHostMarker -or !$logText.Contains('REACH_SELFTEST V21 PASS: real registered client and socket transfer authority, stale generation, detach and subscriber revocation')) { $result.verdict='FAIL' }
        if(!$hasBlockHeaderMarker) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V35 PASS: real shared UDP libutp rejects nearby port, accepts exact ownerless endpoint and retires wrapper')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V135 PASS: actual accepted uTP GetPeerName exact full IPv4 short buffer reports required size unchanged null negative rejected; no authenticated DCO uTP transfer')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V136 PASS: DCO authorized uTP Start real shared UDP connect HELLO exact IPv4 endpoint isolated client retirement; no SecureIdent winner file transfer or physical drain proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V137 PASS: real shared UDP uTP wire HELLOANSWER capabilities challenge PUBLICKEY SIGNATURE fresh RSA DCO adopts original client no TCP observation useful bytes or file proof; no two products public fallback')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V138 PASS: real shared UDP uTP corrupt wire SIGNATURE rejects IdentityMismatch terminal once drains route original hash lifetime credits socket untouched; no file public fallback or physical drain proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V139 PASS: authenticated DCO uTP wire FILESTATUS slot REQUESTPARTS partial4096 duplicate stable final byte real IOCP hash callback VerifiedPart completed4097 disk exact; no F1 public fallback two products')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V140 PASS: actual DCO uTP pending session Close twice detaches before ACK owner cancel drains attempt reservation subscription preserves original; no physical libutp drain proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V141 PASS: known capable client normal TryToConnect recognizes live owned DCO admission no parallel classic socket token state epoch preserved; not initial automatic admission or public fallback')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V142 PASS: capable download normal TryToConnect automatic DCO admission missing QUIC trust BootstrapRequired once no advertised TCP upgrade classic socket or cooldown cascade; no positive public route fallback')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V143 PASS: TCP actual partial4096 socket loss retains owned recovery intent epoch highwater useful bytes no unproven automatic route; subsequent explicit route repair not public fallback')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V144 PASS: actual QUIC loss preserves prepared pinned recovery policy bounded probe cadence rejects changed pin node attempt topology TOFU persistence stale handle without route mutation; no public QUIC recovery or uTP consent')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V145 PASS: simulated public endpoint QUIC Ready loss normal recovery pump fresh PROBE CHALLENGE PROVE signed ACK selector new native handshake HELLOANSWER original adopted epoch2 same attempt file credits token lifetime; no manual local routes file payload physical network or two products')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V146 PASS: control recovery fresh verified higher sequence exact active session old replay wrong endpoint generation attempt peer digest rejected duplicate no TTL renewal expired tombstone rejected alias safe and overflow closed; trusted ledger fixture not wire authentication')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V147 PASS: automatic QUIC Ready loss epoch2 normal filename slot REQUESTPARTS no seeded reservation partial4096 IOCP disk exact duplicate consumed no inflation final real hash completed4097 same attempt; simulated endpoint not Transferring loss F1 two products or physical network')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V148 PASS: automatic QUIC Transferring loss epoch1 useful4096 IOCP disk preserved fresh bootstrap selector AUTH epoch2 same attempt filename slot REQUESTPARTS only4096..4097 old provenance unchanged final byte real hash completed4097 exact; simulated endpoints no F1 two products physical network or expired control session')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V149 PASS: real65s control idle retained high-water fresh automatic bootstrap QUIC AUTH epoch2 requests gap1 hash completed4097 exact; simulated endpoints one host no F1 two products or physical network')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V150 PASS: both original control ledgers expired real65s retained fresh correlated signed renewal old PROVE cookie rejected same download gap1 hash exact4097; remote fixture not second product')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V151 PASS: product server recovery preparation next route above original highwater same attempt epoch1 duplicate no restart; seeded trusted control ledger no wire proof second product or recovered handshake')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V152 PASS: real server consent retained while live retirement removes manager owner and copied ledger reclaims after64s; no live clock advance or new wire permission')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V153 PASS: product server control remote generation differs local topology retained exact remote ledger local lifecycle fence; seeded trusted context not wire peer generation interoperability')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V154 PASS: production block parser 121 malformed headers and bounds reject without timer renewal or download state mutation including I64 overflow; no valid large file write proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V155 PASS: real I64 ProcessBlockPacket accepts offsets4294967294..4294967296 PartFile IOCP sparse disk2542550 exact3 no low range alias; seeded reservation direct parser no transport full F3 or integrity proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V158 PASS: actual TCP HELLO fresh RSA promotes provisional DCO identity before single attach; expected hash alone did not promote')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V159 PASS: actual TCP HELLO fresh RSA provisional identity merges subscribers into known gathering peer source closes before attach zero payload and drained; target has no transport not dual connected session proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V160 PASS: host selects separately evidenced TCP and QUIC rejects stale lifetime hash topology TTL and unrelated UDP pin no Start identity adoption or attempt mutation; seeded observation and UDP proof not physical TCP return-path evidence')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V161 PASS: real1600ms policy preparation before fresh1500ms control deadline then signed ACK4 queued no socket no Core deadline extension; historical zero-PROBE failure class reproduced separately')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V162 PASS: actual Ready DCO winner diagnostic opaque session decimal epoch published immutable cache no endpoint key or authority mutation; GUI and API share cache no HTTP wire assertion')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V163 PASS: terminal Disabled diagnostic retained after actual DCO release zero owner resources opaque id stable no reason rewrite; explicit no route fixture')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V164 PASS: normal per-file Kad6 scheduler signed registered-cap contact bootstrap FIND GET timer source single delivery; simulated witness no physical NAT claim')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V165 PASS: expired signed contact bootstrap CONTACT_GET same-key fresh CONTACT_RESULT before normal FIND GET; simulated witness no physical NAT claim')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V166 PASS: receiver-first activation control bootstrap descriptor/source STORED over real shared loopback UDP; consent withdrawal no reply no RDV; mapping and public UDP verdict injected not physical NAT')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V167 PASS: classic UDP ACK before inbound rejected then real new loopback TCP accept and classic UDP ACK verify mapped external port distinct from bind; router injected not external client or HighID proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V168 PASS: normal manager publishes actual shared file persistent signed serial descriptor/source; lost descriptor one restage lost STORED ACK exact retry one completion; simulated W no physical NAT claim')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V169 PASS: normal index missing source returns complete signed CLOSER over real shared UDP; signed capability withdrawal yields EMPTY; no peer session or route granted')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V170 PASS: current owned mapping readback failure consumed once withdraws grant classic callback and receiver before rediscovery; injected worker result not physical router deletion')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V171 PASS: normal manager and immutable API report BOOTSTRAP_REQUIRED NO_ROUTE and silent W DISCOVERY_UNAVAILABLE; bounded bootstrap sends global lookup deadline cooldown retained; simulated silent W no queue transfer claim')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V172 PASS: normal automatic classic login failure selects second known server once after closing first; duplicate LowID no third login and no HighID; two loopback protocol fixtures not external servers')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V173 PASS: disabling bounded callback fallback restores normal classic SmartID handling on duplicate LowID without another login; loopback fixture no HighID proof')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V174 PASS: actual legacy Kad2 index inserts10000 sources normal stop writes owned profile real restart loader recovers10000 exact duplicate stable drain under30s; no GUI responsiveness 2h20 soak or exit20 cause claim')) { $result.verdict='FAIL' }
        if(!$logText.Contains('REACH_SELFTEST V36 PASS: real shared UDP libutp rejects stale owner generation and unregister removes expectations')) { $result.verdict='FAIL' }
    }
}
if($diagnosticPort -and ($diagnosticSamples -eq 0 -or $diagnosticFailures -ne 0 -or
    $diagnosticSequences.Count -lt 2 -or !$diagnosticWinner -or !$diagnosticTerminal)) { $result.verdict='FAIL' }
[IO.File]::WriteAllText((Join-Path $root 'runtime-evidence.json'),($result|ConvertTo-Json -Depth 4),[Text.Encoding]::UTF8)
Write-Output ($result|ConvertTo-Json -Depth 4)
if($terminal -and $result.verdict -ne 'PASS') { throw 'Runtime selftest failed; evidence retained.' }
if(!$terminal) { throw 'Observation window expired; process not killed and RUNNING evidence retained. Observe this process before starting another test.' }
