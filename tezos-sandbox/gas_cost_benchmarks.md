# Gas cost benchmarks

Below are the gas and storage costs for running the scenarios in `test_zkchannel_pssig.py`. The cost in tez is an estimate from the tezos-sandbox node. 

```
pssig origination
        Storage size: 630 bytes
        Paid storage size diff: 630 bytes
        Consumed gas: 4237.859
        tez: 0.2230409998446703

zkchannel origination
        Storage size: 7424 bytes
        Paid storage size diff: 7424 bytes
        Consumed gas: 30569.921
        tez: 1.931061000097543

addFunding
        Storage size: 7427 bytes
        Paid storage size diff: 3 bytes
        Consumed gas: 31259.290
        tez: 0.003405999857932329

merchClose
        Storage size: 7429 bytes
        Paid storage size diff: 2 bytes
        Consumed gas: 31466.876
        tez: 0.003924000076949596

custClose
    main_zkchannel entry point
        Storage size: 7424 bytes
        Consumed gas: 41077.250
    pssig contract call
        Storage size: 630 bytes
        Consumed gas: 17063.313
    transfer balance to merch
        Consumed gas: 1427
    total tez: 0.007798000238835812

custClaim
        Consumed gas: 1427
        tez: 0.0035910001024603844
```

## Navigation
- [Tutorial part 1 - Setup Instructions](tutorial_pt1_setup.md)
- [Tutorial part 2 - zkChannels](tutorial_pt2_zkchannels.md)