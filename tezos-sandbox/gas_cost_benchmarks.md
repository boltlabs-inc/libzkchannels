# Gas cost benchmarks

Below are the gas and storage costs for running the scenarios in `test_zkchannel_v3.py`. The cost in tez is an estimate from the tezos-sandbox node. 

```
pssig origination
        Storage size: 686 bytes
        Paid storage size diff: 686 bytes
        Consumed gas: 4843.973
        tez: 0.23715800000354648

zkchannel origination
        Storage size: 6250 bytes
        Paid storage size diff: 6250 bytes
        Consumed gas: 28428.318
        tez: 1.6361730000935495

addFunding
        Storage size: 6252 bytes
        Paid storage size diff: 2 bytes
        Consumed gas: 29121.203
        tez: 0.0036919997073709965

merchClose
        Storage size: 6256 bytes
        Paid storage size diff: 4 bytes
        Consumed gas: 29330.561
        tez: 0.004210999701172113

custClose
    main_zkchannel entry point
        Storage size: 6256 bytes
        Consumed gas: 39289.103
    pssig contract call
        Storage size: 686 bytes
        Consumed gas: 17527.553
    transfer balance to merch
        Consumed gas: 1427
    total tez: 0.007546999957412481

custClaim
        Consumed gas: 1427
        tez: 0.0033770003356039524
```

## Navigation
- [Tutorial part 1 - Setup Instructions](tutorial_pt1_setup.md)
- [Tutorial part 2 - zkChannels](tutorial_pt2_zkchannels.md)
