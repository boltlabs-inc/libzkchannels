# Bootstrap1 (cust) sk
# edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh

# Bootstrap2 (merch) sk
# edsk39qAm1fiMjgmPkw1EgQYkMzkJezLNewd7PLNHTkr6w9XA2zdfo

from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface

pssig_code = Contract.from_file('mock_pssig3.tz')

out = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').origination(script=pssig_code.script()).autofill().sign().inject()

input("Bake to confirm origination of pssig contract, then hit enter continue.")

opg = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').shell.blocks[-5:].find_operation(out['hash'])

pssig_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]

main_code = Contract.from_file('zkchannel_mock_ps3.tz')

main_storage = {'chanID': '123456789ccc', 
'custAddr': 'tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx', 
'custBal':0, 
'custFunding': 20000000, 
'custPk': 'edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav', 
'delayExpiry': '1970-01-01T00:00:00Z', 
'merchAddr': 'tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN', 
'merchBal': 0, 
'merchFunding': 10000000, 
'merchPk': 'edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9', 
'pssigContract': pssig_id, 
'revLock': '1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49', 
'selfDelay': 3, 
'status': 'awaitingFunding'}

out = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').origination(script=main_code.script(storage=main_storage)).autofill().sign().inject()

input("Bake a block to confirm origination of zkchannel contract.")

opg = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').shell.blocks[-5:].find_operation(out['hash'])

main_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]

cust_ci = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').contract(main_id)

merch_ci = pytezos.using(shell='http://localhost:18731', key='edsk39qAm1fiMjgmPkw1EgQYkMzkJezLNewd7PLNHTkr6w9XA2zdfo').contract(main_id)

watchtower_command = "python3 passive_zkchannel_watchtower.py --contract {cid} --network http://localhost:18731 --identity merchant".format(cid=main_id)

print("Run the watchtower with \n" + watchtower_command)

cust_ci.addFunding('').with_amount(20000000).inject()

input("Bake to add cust funding")

merch_ci.addFunding('').with_amount(10000000).inject()

input("Bake to add merch funding")

# print(merch_ci.merchClose("").cmdline())
merch_ci.merchClose("").inject()

input("Bake to confirm merchClose")

close_storage = {
    "custBal": 1 * 1000000,
    "custBalB": "01312D00",
    "g2": "12345678fff3",
    "merchBal": 29 * 1000000,
    "merchBalB": "00989680",
    "merchPk0": "12345678fff4",
    "merchPk1": "12345678fff5",
    "merchPk2": "12345678fff6",
    "merchPk3": "12345678fff7",
    "merchPk4": "12345678fff8",
    "revLock": "90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729",
    "revLockB": "80d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d728",
    "s1": "12345678fff1",
    "s2": "12345678fff2"
}

# print(cust_ci.custClose(close_storage).cmdline())
cust_ci.custClose(close_storage).inject()

input("Bake to confirm custClose")

cust_ci.custClaim("").inject()
print("Bake to confirm custClaim and close the channel")

# # Alternatively, to close the channel with merchDispute, run:
# rev_secret = "123456789ccc"
# merch_ci.dis(close_storage).inject()
# print("Bake to confirm merchDispute and close the channel")

