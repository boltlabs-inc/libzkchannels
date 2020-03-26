import time
import subprocess

total_open = 0
total_init = 0
total_activate = 0
total_unlink = 0
total_pay = 0
total_close = 0
nr = 10
for i in range(0, nr):
    start = time.time()
    # Open
    p = subprocess.Popen(["./target/release/zkchannels-mpc", "open", "--cust-bal", "9000", "--merch-bal", "0", "--dust-limit", "100", "--other-port", "8181", "--own-port", "8080", "--party", "CUST"])
    p2 = subprocess.Popen(["./target/release/zkchannels-mpc", "open", "--dust-limit", "100", "--other-port", "8080", "--own-port", "8181", "--party", "MERCH"])
    p.wait()
    p2.wait()
    p.terminate()
    p2.terminate()
    end_open = time.time()
    total_open += end_open - start
    # print("Open: " + str(end_open - start))
    #Init
    p2 = subprocess.Popen(["./target/release/zkchannels-mpc", "init", "--other-port", "8080", "--own-port", "8181", "--party", "MERCH"])
    p = subprocess.Popen(["./target/release/zkchannels-mpc", "init", "--txid", "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1", "--index", "0", "--input-sats", "10000", "--output-sats", "9000", "--other-port", "8181", "--own-port", "8080", "--party", "CUST"])
    p.wait()
    p2.wait()
    p.terminate()
    p2.terminate()
    end_init = time.time()
    total_init += end_init - end_open
    # print("Init: " + str(end_init - end_open))
    #Activate
    p2 = subprocess.Popen(["./target/release/zkchannels-mpc", "activate", "--other-port", "8080", "--own-port", "8181", "--party", "MERCH"])
    p = subprocess.Popen(["./target/release/zkchannels-mpc", "activate", "--other-port", "8181", "--own-port", "8080", "--party", "CUST"])
    p.wait()
    p2.wait()
    p.terminate()
    p2.terminate()
    end_activate = time.time()
    total_activate += end_activate - end_init
    # print("Activate: " + str(end_activate - end_init))
    #Unlink
    p2 = subprocess.Popen(["./target/release/zkchannels-mpc", "unlink", "--other-port", "8080", "--own-port", "8181", "--party", "MERCH"])
    p = subprocess.Popen(["./target/release/zkchannels-mpc", "unlink", "--other-port", "8181", "--own-port", "8080", "--party", "CUST"])
    p.wait()
    p2.wait()
    p.terminate()
    p2.terminate()
    end_unlink = time.time()
    total_init += end_unlink - end_activate
    # print("Unlink: " + str(end_unlink - end_activate))
    #Pay
    p2 = subprocess.Popen(["./target/release/zkchannels-mpc", "pay", "--amount", "200", "--other-port", "8080", "--own-port", "8181", "--party", "MERCH"])
    p = subprocess.Popen(["./target/release/zkchannels-mpc", "pay", "--amount", "200", "--other-port", "8181", "--own-port", "8080", "--party", "CUST"])
    p.wait()
    p.terminate()
    p2.terminate()
    end_pay = time.time()
    total_pay += end_pay - end_unlink
    # print("Pay: " + str(end_pay - end_unlink))

print("Open: " + str(total_open/nr))
print("Init: " + str(total_init/nr))
print("Activate: " + str(total_activate/nr))
print("Unlink: " + str(total_unlink/nr))
print("Pay: " + str(total_pay/nr))
