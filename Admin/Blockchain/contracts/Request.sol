// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import { G } from "../libraries/G.sol";
import {Params} from "./Params.sol";
import {Accumulator} from "./Accumulator.sol";

contract Request {
    Params private params;
    address private owner;
    Accumulator private acc;

    constructor(Params _params, Accumulator _acc) {
        owner = msg.sender;
        params = _params;
        acc = _acc;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function set_params(address addr) public onlyOwner {
        params = Params(addr);
    }
    
    struct Ciphershare {
        G.G2Point[2] X;
    }
  
    struct Compresser{
        G.G1Point[] commitments;
        Ciphershare[] ciphershares;
    }

    struct G2PointCompresser {
        G.G2Point[] Dw;
        G.G2Point[] Ew;
    }

    struct IssueProof {
        uint256 c;
        uint256 rr;
        uint256[] ros;
        uint256[][] total_rm;
        string[] combination;
    }

    struct OpenProof {
        uint256[] c;
        uint256[] rr;
        uint256[][] rs;  
    }
    
    struct Vcert {
        G.G1Point commit;
        uint256[2] signature;
    }
    
    event emitRequest(uint256 indexed id, address sender, uint256[4][] vcerts, uint256[2] cm, uint256[2][] commitments, uint256[8][] ciphershares, string[] public_m, string[] combination,uint256[] validator_shares,uint256[] opener_shares);

    function check_hr_bo(string memory name, G.G1Point[] memory commitments, Ciphershare[] memory ciphershares, G.G1Point memory h, G.G1Point[][] memory hidden_p, G.G1Point[] memory hr, G.G2Point[] memory bo) private view returns(bool) {
        G.G1Point[] memory p_X = new G.G1Point[](commitments.length + 3);
        G.G2Point[] memory p_Y = new G.G2Point[](commitments.length + 3);
        G.G2Point[] memory beta =  params.get_beta(name);
        G.G2Point[] memory opk =  params.get_opk(name);
        for(uint256 i = 0; i< hr.length; i++) {
            uint256 j = 0;
            for(j=0; j< bo.length; j++) {
                G.G1Point memory tmp = G.G1Point(0,0); //= G.g1mul(hidden_p[j][0], (i+1));
                for(uint256 l=1; l < 1+hidden_p[j].length; l++) {
                    tmp = G.g1add(tmp, G.g1mul(hidden_p[j][l-1], (i+1) ** l));
                }
                p_X[j] = G.g1add(commitments[j], tmp);
                p_Y[j] = beta[j];
            }
            p_X[j] = hr[i];
            p_X[j+1] = G.g1neg(h);
            p_X[j+2] = G.g1neg(G.P1());
            
            p_Y[j] = opk[i];
            p_Y[j+1] = ciphershares[i].X[1];
            p_Y[j+2] = G.ec_sum(bo);
            
            if(!G.pairing(p_X, p_Y)) {
                return false;
            }
        }
        return true;
    }

    function check_open_proof(string memory name, OpenProof memory proof, G.G1Point memory cm, Compresser memory compressed_params,  G2PointCompresser memory compressedG2points, G.G1Point[][] memory hidden_p, G.G1Point[] memory hr, G.G2Point[] memory bo) private view returns (bool) {
        assert(verify_Dw(compressedG2points.Dw, compressed_params.ciphershares, proof));
        assert(verify_Ew(name, compressedG2points.Ew, compressed_params.commitments, compressed_params.ciphershares, proof));
        G.G1Point memory h = G.HashToPoint(uint256(G.G1_to_binary256(cm)));
        G.G1Point[] memory hs = params.get_hs(name);
        for(uint256 i=0; i<proof.rr.length; i++) {
            if(proof.c[i] != ToChallengeOpen(h, compressedG2points.Dw[i], compressedG2points.Ew[i], hs)) {
                return false;
            }
        }
        return (check_hr_bo(name, compressed_params.commitments, compressed_params.ciphershares, h, hidden_p, hr, bo));
    }

    function check_issue_proof(string memory name, IssueProof memory proof, G.G1Point memory cm, Compresser memory compressed_params, Vcert[] memory vcerts) private view returns (bool) {
        G.G1Point[] memory Aw = calculate_Aw(name, proof.combination, compressed_params.commitments, cm, proof);
        G.G1Point memory Bw = calculate_Bw(name, proof.combination, cm, proof);
        G.G1Point[] memory Cw = calculate_Cw(proof.combination, vcerts, proof); 
        return (proof.c == ToChallengeIssue(cm, G.HashToPoint(uint256(G.G1_to_binary256(cm))), Bw, params.get_hs(name), Aw, Cw));
    }

    function check_Vcerts(string memory name, Vcert[] memory vcerts, IssueProof memory iproof) private view returns(bool) {
        // require(isRequested(name, vcerts[0]), "Verifiable certificate already used.");
        bool evaluated;
        string[] memory combination = iproof.combination;
        require (vcerts.length == combination.length, "Bad combination.");
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        //require(params.checkCombination(id, combination), "Bad combination.");
        for (uint256 i = 0; i < vcerts.length; i++) {//each Vcert is done ECC verification
            evaluated = G.do_ecdsa_verify(vcerts[i].commit, params.get_ttpKeys(combination[i]), vcerts[i].signature);
            if(!evaluated) {
                return false;
            }
        }
        require(check_sk(iproof), "master secret key verification failed");
        return true;
    }

    function check_sk(IssueProof memory proof) private pure returns(bool) {
        for (uint256 i=1; i < proof.total_rm.length-1; i++) {  // both private and public attributes proof is included.
            if(proof.total_rm[0][0] != proof.total_rm[i][0]) {
                return false;
            }
        }
        return true;
    }

    function RequestCred(string memory name, Vcert[] memory vcerts, G.G1Point memory cm, Compresser memory compressed_params, G.G1Point[][] memory hidden_p, G.G1Point[] memory hr, G.G2Point[] memory bo, IssueProof memory iproof, OpenProof memory oproof, G2PointCompresser memory compressedG2points, string[] memory public_m) public {
        //Below 3 checks must be made local
        require(check_Vcerts(name, vcerts, iproof), "Verifiable certificate verification failed");//Vcert verification
        require(check_issue_proof(name, iproof, cm, compressed_params, vcerts), "issuance ZKPoK verification failed");//Issuance verification
        require(check_open_proof(name, oproof, cm, compressed_params, compressedG2points, hidden_p, hr, bo), "Opening ZKPoK verification failed");//Opening Verification
        (uint256[] memory validator_shares, uint256[] memory opener_shares) = acc.generate_kr_shares(cm);
        logging(name, msg.sender, vcerts, cm, compressed_params, public_m, iproof.combination, validator_shares, opener_shares);
        //Need to send iproof, oproof, compressedG2points, hidden_p, hr, bo also to Validator
        //Can do Opener verification at opener itself. Then, get true from all and then perform logging.
        //"hidden_p": product of hash of commitment and m polynomials that hide private attributes
        //"hr": product of hash of commitment and random number
        //"bo": product of aggregated validator key and random number array "os"
    }

    function logging(string memory name, address sender, Vcert[] memory certs, G.G1Point memory cm, Compresser memory compressed_params, string[] memory public_m, string[] memory combination,uint256[] memory validator_shares,uint256[] memory opener_shares) private {
        uint256[4][] memory vcerts = new uint256[4][](certs.length); // [cert.commit.X, cert.commit.Y, cert.signature[0], cert.signature[1]];
        for (uint256 i=0;i<certs.length;i++) {
            vcerts[i][0] = certs[i].commit.X;
            vcerts[i][1] = certs[i].commit.Y;
            vcerts[i][2] = certs[i].signature[0];
            vcerts[i][3] = certs[i].signature[1];
        }
        uint256[2] memory commitment = [cm.X, cm.Y];
        uint256[2][] memory X = new uint256[2][](compressed_params.commitments.length);
        for (uint256 i=0;i<compressed_params.commitments.length;i++) {
            X[i][0] = compressed_params.commitments[i].X;
            X[i][1] = compressed_params.commitments[i].Y;
        }
        uint256[8][] memory Y = new uint256[8][](compressed_params.ciphershares.length);
        for(uint256 i=0; i<compressed_params.ciphershares.length;i++){
            Y[i][0] = compressed_params.ciphershares[i].X[0].X[0];
            Y[i][1] = compressed_params.ciphershares[i].X[0].X[1];
            Y[i][2] = compressed_params.ciphershares[i].X[0].Y[0];
            Y[i][3] = compressed_params.ciphershares[i].X[0].Y[1];
            Y[i][4] = compressed_params.ciphershares[i].X[1].X[0];
            Y[i][5] = compressed_params.ciphershares[i].X[1].X[1];
            Y[i][6] = compressed_params.ciphershares[i].X[1].Y[0];
            Y[i][7] = compressed_params.ciphershares[i].X[1].Y[1];
        }
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");

        // Requested[id][cert.commit.X][cert.commit.Y] = true;
        emit emitRequest(id, sender, vcerts, commitment, X, Y, public_m, combination, validator_shares,opener_shares);
    }

    function calculate_Aw(string memory name, string[] memory combination, G.G1Point[] memory commitments, G.G1Point memory cm, IssueProof memory proof) private view returns (G.G1Point[] memory) {
        uint256[] memory ros = proof.ros;
        G.G1Point[] memory Aw = new G.G1Point[](ros.length);
        uint256[][] memory total_rm = proof.total_rm;
        uint256[] memory rm = new uint256[](proof.ros.length + total_rm[total_rm.length-1].length);
        uint256 k = 0;
        uint256[][] memory include_indexes = params.get_include_indexes(name, combination);
        for (uint256 i = 0; i < total_rm.length - 1; i++) {
            for (uint256 j = 0; j < total_rm[i].length; j++) {
                if (include_indexes[i][j] == 1){
                    rm[k] = total_rm[i][j];
                    k = k+1;
                }
            }
        }
        for (uint256 i=0; i< total_rm[total_rm.length-1].length; i++) {
            rm[k] =  total_rm[total_rm.length-1][i];
            k = k+1;
        } 
        G.G1Point memory h = G.HashToPoint(uint256(G.G1_to_binary256(cm)));
        for(uint256 i=0; i < ros.length; i++) {
            Aw[i] = G.g1add(G.g1mul(commitments[i], proof.c), G.g1add(G.g1mul(G.P1(), ros[i]), G.g1mul(h, rm[i])));
        }
        return Aw;
    }

    function calculate_Bw(string memory name, string[] memory combination, G.G1Point memory cm, IssueProof memory proof) private view returns (G.G1Point memory) {
        uint256 c = proof.c;
        uint256 rr = proof.rr;
        uint256[][] memory total_rm = proof.total_rm;
        uint256[] memory rm = new uint256[](proof.ros.length + total_rm[total_rm.length-1].length);
        uint256 k = 0;
        uint256[][] memory include_indexes = params.get_include_indexes(name, combination);
        for (uint256 i = 0; i < total_rm.length - 1; i++) {
            for (uint256 j = 0; j < total_rm[i].length; j++) {
                if (include_indexes[i][j] == 1){
                    rm[k] = total_rm[i][j];
                    k = k+1;
                }
            }
        }
        for (uint256 i=0; i< total_rm[total_rm.length-1].length; i++) {
            rm[k] =  total_rm[total_rm.length-1][i];
            k = k+1;
        }
        G.G1Point[] memory hs = params.get_hs(name);
        G.G1Point memory Bw = G.g1add(G.g1mul(cm, c), G.g1mul(G.P1(), rr));
        for(uint256 i=0; i< rm.length; i++) {
            Bw = G.g1add(Bw, G.g1mul(hs[i], rm[i]));
        }
        return Bw;
    }

    function verify_Dw(G.G2Point[] memory Dw, Ciphershare[] memory ciphershares, OpenProof memory proof) private view returns(bool) {
        // Dw and rr should be same length
        G.G1Point[] memory AA = new G.G1Point[](3);
        G.G2Point[] memory AB = new G.G2Point[](3);
        for(uint256 i=0; i< Dw.length; i++) {
            AA[0] = G.g1mul(G.P1(), proof.c[i]);
            AA[1] = G.g1mul(G.P1(), proof.rr[i]);
            AA[2] = G.g1neg(G.P1());
            AB[0] = ciphershares[i].X[0];
            AB[1] = G.P2();
            AB[2] = Dw[i];
            if (!G.pairing(AA, AB)) {
                return false;
            }
        }
        return true;
    }

    function verify_Ew(string memory name, G.G2Point[] memory Ew, G.G1Point[] memory commitments, Ciphershare[] memory ciphershares, OpenProof memory proof) private view returns(bool) {
        G.G1Point[] memory AA = new G.G1Point[](3 + commitments.length);
        G.G2Point[] memory AB = new G.G2Point[](3 + commitments.length);
        G.G2Point[] memory beta =  params.get_beta(name); // Name of AC.
        G.G2Point[] memory opk =  params.get_opk(name);
        for(uint256 i=0; i< Ew.length; i++) {
            AA[0] = G.g1neg(G.P1());
            AB[0] = Ew[i];
            AA[1] = G.g1mul(G.P1(), proof.rr[i]);
            AB[1] = opk[i];
            AA[2] = G.g1mul(G.P1(), proof.c[i]);
            AB[2] = ciphershares[i].X[1];
            for(uint256 j=0; j < commitments.length; j++) {
                AA[j+3] = G.g1mul(G.P1(), proof.rs[i][j]);
                AB[j+3] = beta[j]; 
            }
            if (!G.pairing(AA, AB)) {
                return false;
            }
        }
        return true;
    }

    function calculate_Cw(string[] memory combination, Vcert[] memory vcerts, IssueProof memory proof) private view returns(G.G1Point[] memory){
        uint256[][] memory total_rm = proof.total_rm;
        uint256 c = proof.c;
        G.G1Point[] memory Cw = new G.G1Point[](total_rm.length - 1);
        for (uint256 i = 0;  i < total_rm.length - 1; i++) {
            G.G1Point[] memory hs = params.get_ttp_params(combination[i]);
            G.G1Point memory tmp = G.g1mul(vcerts[i].commit, c);
            tmp = G.g1add(tmp, G.g1mul(G.P1(), total_rm[i][total_rm[i].length-1]));
            for (uint256 j = 0; j < total_rm[i].length - 1; j++) {
                tmp = G.g1add(tmp, G.g1mul(hs[j], total_rm[i][j]));
            }
            Cw[i] = tmp;
        }
        return Cw;
    }

    function ToChallengeIssue(G.G1Point memory cm, G.G1Point memory h, G.G1Point memory Bw, G.G1Point[] memory hs, G.G1Point[] memory Aw, G.G1Point[] memory Cw)
                                        internal pure returns (uint256) {
        bytes memory Cstring = new bytes(160 + (hs.length + Aw.length + Cw.length) * 32);
        bytes32 X = G.G1_to_binary256(G.P1());
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i] = X[i];
        }
        X = G.G2_to_binary256(G.P2());
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+32] = X[i];
        }
        X = G.G1_to_binary256(cm);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+64] = X[i];
        }
        X = G.G1_to_binary256(h);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+96] = X[i];
        }
        X = G.G1_to_binary256(Bw);
        for (uint256 i=0; i < 32 ; i++) {
            Cstring[i+128] = X[i];
        }
        
        uint256 location = 160;
        for(uint256 i=0; i < hs.length; i++) {
            X = G.G1_to_binary256(hs[i]);
            for (uint256 j=0; j < 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }
        for(uint256 i=0; i< Aw.length; i++){
            X = G.G1_to_binary256(Aw[i]);
            for (uint256 j=0; j < 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }
        for(uint256 i=0; i< Cw.length; i++){
            X = G.G1_to_binary256(Cw[i]);
            for (uint256 j=0; j < 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }

        bytes32 Chash =  sha256(Cstring);
        return uint256(Chash);
    }


    function ToChallengeOpen(G.G1Point memory h, G.G2Point memory Aw, G.G2Point memory Bw, G.G1Point[] memory hs)
                                        internal pure returns (uint256) {
        bytes memory Cstring = new bytes(160 + (hs.length) * 32);
        bytes32 X = G.G1_to_binary256(G.P1());
        uint256 i = 0;
        for (i=0; i< 32 ; i++) {
            Cstring[i] = X[i];
        }
        X = G.G2_to_binary256(G.P2());
        for (i=0; i< 32 ; i++) {
            Cstring[i+32] = X[i];
        }
        X = G.G1_to_binary256(h);
        for (i=0; i< 32 ; i++) {
            Cstring[i+64] = X[i];
        }
        X = G.G2_to_binary256(Aw);
        for (i=0; i< 32 ; i++) {
            Cstring[i+96] = X[i];
        }
        X = G.G2_to_binary256(Bw);
        for (i=0; i< 32 ; i++) {
            Cstring[i+128] = X[i];
        }
        
        uint256 location = 160;
        uint256 j = 0;
        for(i=0; i < hs.length; i++) {
            X = G.G1_to_binary256(hs[i]);
            for (j=0; j< 32 ; j++) {
                Cstring[j+location] = X[j];
            }
            location = location + 32;
        }
        bytes32 Chash =  sha256(Cstring);
        return uint256(Chash);
    }
}