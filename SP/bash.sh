python3 init.py

python3 AttributeCertifier.py --title "Identity_Certificate" --name IdP --req-ip 127.0.0.1 --req-port 3001  --open-ip 127.0.0.1 --open-port 7001 --address $(grep "admin=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547" < Identity_input.txt
python3 AttributeCertifier.py --title "Income_Certificate" --name Employer --req-ip 127.0.0.1 --req-port 3002  --open-ip 127.0.0.1 --open-port 7002 --dependency "Identity_Certificate" --address $(grep "admin=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547" < Income_input.txt

python3 Anony_cred.py --title "Loan_Credential" --name Loaner --ip 127.0.0.1 --port 4000 --dependency "Identity_Certificate" "Income_Certificate" --address $(grep "admin=" addresses.txt | cut -d "=" -f 2) --validator-addresses $(grep "validator1=" addresses.txt | cut -d "=" -f 2) $(grep "validator2=" addresses.txt | cut -d "=" -f 2) $(grep "validator3=" addresses.txt | cut -d "=" -f 2) --opener-addresses $(grep "opener1=" addresses.txt | cut -d "=" -f 2) $(grep "opener2=" addresses.txt | cut -d "=" -f 2) $(grep "opener3=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"

python3 Validator.py --title "Loan_Credential" --id 1 --address $(grep "validator1=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"
python3 Validator.py --title "Loan_Credential" --id 2 --address $(grep "validator2=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"
python3 Validator.py --title "Loan_Credential" --id 3 --address $(grep "validator3=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"

python3 Opener.py --title "Loan_Credential" --id 1 --ip 127.0.0.1 --port 8001 --address $(grep "opener1=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"
python3 Opener.py --title "Loan_Credential" --id 2 --ip 127.0.0.1 --port 8002 --address $(grep "opener2=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"
python3 Opener.py --title "Loan_Credential" --id 3 --ip 127.0.0.1 --port 8003 --address $(grep "opener3=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547"

python3 User.py --unique-name user1 --address $(grep "user1=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547" < User_input.txt
python3 User.py --unique-name user2 --address $(grep "user2=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547" < User_input.txt

python3 Service_provider.py --title "Loan_Service" --name Bank --address $(grep "SP=" addresses.txt | cut -d "=" -f 2) --rpc-endpoint "http://127.0.0.1:7547" --accepts "Loan_Credential" --ip "127.0.0.1" --port "9000"

python3 Service_revoke.py --title "Loan_Credential" --rpc-endpoint "http://127.0.0.1:7547"