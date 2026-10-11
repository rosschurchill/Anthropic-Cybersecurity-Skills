# Network-Level DCOM Detection with Zeek

```bash
# Zeek script for detecting DCOM lateral movement at the network level
# Monitors RPC Endpoint Mapper (port 135) and subsequent high-port connections

cat > /opt/zeek/share/zeek/site/custom-detections/dcom-lateral-movement.zeek << 'ZEEKEOF'
@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dce-rpc

module DCOMLateralMovement;

export {
    redef enum Notice::Type += {
        DCOM_Lateral_Movement_Suspected,
        DCOM_RPC_Scan
    };

    # Threshold for unique targets receiving RPC connections from single source
    const rpc_target_threshold: count = 3 &redef;
    const rpc_time_window: interval = 10min &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="dcom.rpc_targets",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="detect-dcom-lateral",
        $epoch=rpc_time_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["dcom.rpc_targets"]$unique + 0.0;
        },
        $threshold=rpc_target_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=DCOM_RPC_Scan,
                $msg=fmt("Host %s connected to %d hosts on RPC/135 in %s - possible DCOM lateral movement",
                         key$str, result["dcom.rpc_targets"]$unique, rpc_time_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 135/tcp && c$id$resp_h in Site::local_nets )
    {
        SumStats::observe("dcom.rpc_targets",
            [$str=cat(c$id$orig_h)],
            [$str=cat(c$id$resp_h)]
        );
    }
}
ZEEKEOF

# Monitor DCE-RPC operations related to DCOM objects
cat /opt/zeek/logs/current/dce_rpc.log | \
  zeek-cut ts id.orig_h id.resp_h endpoint operation | \
  grep -iE "IDispatch|IRemoteActivation|IRemUnknown|IObjectExporter" | \
  sort -t$'\t' -k2 | uniq -c | sort -rn

# Track RPC endpoint mapper connections between internal hosts
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 == 135' | \
  awk '{print $2, "->", $3}' | sort | uniq -c | sort -rn | head -20
```
