from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface

code = """
parameter bytes;
storage (pair :storage (big_map bytes timestamp) nat);
code { DUP ;
       DIP { CDR @storage_slash_1 } ;
       CAR @hash_slash_2 ;
       PUSH nat 1 ;
       { DIP { { DIP { DUP @storage } ; SWAP } } ; SWAP } ;
       CDR %counter ;
       ADD @counter ;
       { DIP { { DIP { DUP @storage } ; SWAP } } ; SWAP } ;
       CAR %records ;
       NOW ;
       { DIP { { DIP { { DIP { DUP @hash } ; SWAP } } ; SWAP } } ; SWAP } ;
       DIP { SOME } ;
       DIP { DIP { DIP { DIP { DROP ; DROP } } } } ;
       UPDATE @records ;
       PAIR %records %counter ;
       NIL operation ;
       PAIR }
"""

contract = Contract.from_michelson(code)

res = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').origination(script=contract.script()).autofill().sign().inject()

input("Bake a block then hit enter.")

opg = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').shell.blocks[-5:].find_operation(res['hash'])

contract_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]

ci = pytezos.using(shell='http://localhost:18731', key='edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh').contract(contract_id)

watchtower_command = "python3 passive_watchtower.py -contract {cid} --network http://localhost:18731".format(cid=contract_id)

print("Run the watchtower with \n" + watchtower_command)

while True:
    input("Press Enter to update the contract via a transfer operation.")
    ci.call('deadbeef').inject()
    print("Bake a block.")
