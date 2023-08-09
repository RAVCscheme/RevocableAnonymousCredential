// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
import { G } from "../libraries/G.sol";
import {Params } from "./Params.sol";
contract Accumulator{

    address private owner;
    Params private params;
    G.G1Point private delta;
    uint randNonce = 0;
    uint private no;
    uint private to;
    uint private nv;
    uint private tv;
    //uint256[] private validators_share;
    //uint256[] private openers_share;
    uint256[] private accumulator_key_shares;
    uint256[] private delta_shares;
    uint256[] private combine_di;
    uint256[] private combine_ei;
    uint256[] private combine_si;
    mapping(uint256 => uint256) private id_kr;
    mapping(uint256 => uint256) private flag;
    uint256[2][] whitelist;
    uint256[2][] blacklist;
    uint256[] a_poly;
    uint256[] b_poly;
    uint256[] c_poly;
    uint256[] a_share;
    uint256[] b_share;
    uint256[] c_share;
    constructor(Params _params) {
        owner = msg.sender;
        params = _params;  
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    event send_W_kr(uint256[2] W, uint256 request_id, uint256 kr, uint256 timestamp);
    //event send_W_kr(uint256[2] W,G.G1Point delta, uint256 request_id);
    event revocation_complete(uint256 c);
    event send_d_and_e(uint256 d, uint256 e);
    event send_s(uint256 s);
    event send_updated_witness(G.G1Point delta);
    event send_self_revocation(uint256 kr, uint256[] W,uint256[] H,uint256[] S, uint256[2][] cm, uint256[] g1_r, uint256[] a_share, uint256[] b_share, uint256[] c_share);

    function lagrange_basis(uint[] memory indexes) public view returns(uint256[] memory){
            uint256 o = G.GEN_ORDER;
            uint256[] memory l = new uint256[](indexes.length);
            for(uint a=0; a<indexes.length; a++){
                uint256 numerator =1;
                uint256 denominator = 1;
                for(uint b=0;b<indexes.length; b++){
                    uint256 i = indexes[a];
                    uint256 j = indexes[b];
                    if (j > i){
                        numerator = mulmod(numerator, j, o);
                        denominator = mulmod(denominator, (j-i), o);
                    }
                    else if(j < i){
                        numerator = mulmod(o - j,numerator, o);
                        denominator = mulmod(denominator, (i-j), o);
                    }
                }
                l[a] = mulmod(numerator, G._modInv(denominator, o), o);
            }
            return l;

    }
    // function genAggregatedYa() public view returns(G.G1Point memory){
    //         uint256 [] memory indexes = new uint[](to);
    //         uint256[2][] memory filter = new uint[2][](to);
    //         uint u = 0;
    //         for (uint i=1; i<=no; i++) 
    //         {
    //             if(accumulator_key_shares[i] != 0){
    //                 indexes[u] = i;
    //                 filter[u] = accumulator_key_shares[i];
    //                 u++;
    //             }
    //         }
    //         uint256[] memory l = lagrange_basis(indexes);
    //         uint256 aggr_ka = 0;
    //         // aggr_ka.X = filter[0][0];
    //         // aggr_ka.Y = filter[0][1];
    //         // aggr_ka = G.g1mul(aggr_ka, l[0]);
    //         for (uint i=0; i<indexes.length; i++){
    //             // G.G1Point memory tmp;
    //             // tmp.X = filter[i][0];
    //             // tmp.Y = filter[i][1];
    //             //aggr_ka = G.g1add(aggr_ka ,(G.g1mul(tmp, l[i])));
    //             aggr_ka = aggr_ka + mulmod(l[i], accumulator_key_shares[indexes[i]-1],G.GEN_ORDER)
    //         }
    //         return aggr_ka;
    // }

    // function genAggregatedYa_2() public view returns(G.G1Point memory){
    //         uint256 [] memory indexes = new uint[](to);
    //         uint256[2][] memory filter = new uint[2][](to);
    //         uint u = 0;
    //         for (uint i=1; i<=no; i++) 
    //         {
    //             if(delta_shares[i]!= 0){
    //                 indexes[u] = i;
    //                 filter[u] = delta_shares[i];
    //                 u++;
    //             }
    //         }
    //         uint256[] memory l = lagrange_basis(indexes);
    //         uint256 aggr_ka;
    //         // aggr_ka.X = filter[0][0];
    //         // aggr_ka.Y = filter[0][1];
    //         // aggr_ka = G.g1mul(aggr_ka, l[0]);
    //         for (uint i=1; i<indexes.length; i++){
    //             // G.G1Point memory tmp;
    //             // tmp.X = filter[i][0];
    //             // tmp.Y = filter[i][1];
    //             // aggr_ka = G.g1add(aggr_ka ,(G.g1mul(tmp, l[i])));
    //             aggr_ka = aggr_ka + mulmod(l[i], delta_shares[indexes[i]-1],G.GEN_ORDER)
    //         }
    //         return aggr_ka;
    // }

    function updateDelta(uint256 ya, uint256 kr) public {
            delta = G.g1mul(delta, G._modInv(addmod(kr,ya,G.GEN_ORDER),G.GEN_ORDER));
    }
    function get_delta() public view returns(uint256, uint256){
        return (delta.X, delta.Y);
    }
    function recieve_share_for_revocation(uint id, uint256 share, uint256 request_id) public {
        if(flag[request_id] == 2) return;

        delta_shares[id-1]= share;
        uint count = 0;
        for (uint i=1; i<=no; i++) 
        {
            if(delta_shares[i-1] != 0) count++;
        }
        if(count==to){
            delta = G.g1mul(delta, aggregate_value(5));       
            for (uint i=1; i<=no; i++) 
            {
               delta_shares[i-1] = 0;
            }

            blacklist.push([id_kr[request_id],block.timestamp]);
            flag[request_id] = 2;
            emit revocation_complete(1);
            //emit send_W_kr(W,request_id,id_kr[request_id], block.timestamp);
        }
    }

    function aggregate_value(uint256 fl) view public returns(uint256){
            uint256 [] memory indexes = new uint[](to);
            uint256[] memory filter = new uint[](to);
            uint256[] memory combine;
            if(fl == 1) combine= combine_di;
            else if(fl == 2) combine = combine_ei;
            else if(fl == 3) combine = combine_si;
            else if(fl == 4) combine = accumulator_key_shares;
            else combine = delta_shares;
            uint u = 0;
            for (uint i=1; i<=no; i++) 
            {
                if(combine[i-1] != 0){
                    indexes[u] = i;
                    filter[u] = combine[i-1];
                    u++;
                }
            }
            uint256[] memory l = lagrange_basis(indexes);
            uint256 aggr = 0;
            for (uint i=0; i<indexes.length; i++){
                aggr = addmod(aggr, mulmod(filter[i], l[i], G.GEN_ORDER), G.GEN_ORDER);
            }
            return aggr;
    }
    function combine_di_and_ei(uint256 di, uint256 ei, uint256 id) public{
            combine_di[id-1] = di;
            combine_ei[id-1] = ei;
            uint count = 0;
            for (uint i=1; i<=no; i++)
            {
                if(combine_di[i-1] != 0) count++;
            }
            if(count==to){
                uint256 d = aggregate_value(1);
                uint256 e = aggregate_value(2);

                for (uint i=1; i<=no; i++) 
                {
                    combine_di[i-1] = 0;
                    combine_ei[i-1] = 0;
                }
                emit send_d_and_e(d,e);
            }
    }
    function combine_func_si(uint256 si, uint256 id) public{
            combine_si[id-1] = si;
            uint count = 0;
            for (uint i=1; i<=no; i++)
            {
                if(combine_si[i-1] != 0) count++;
            }
            if(count==to){
                uint256 s = aggregate_value(3);

                for (uint i=1; i<=no; i++) 
                {
                    combine_si[i-1] = 0;
                }
                emit send_s(s);
            }
    }
    function gen_beaver_tuples(G.G1Point[] memory pub_key) public returns (G.G1Point memory){
        uint256 a = gen_random();
        uint256 b = gen_random();
        uint256 r = gen_random();
        uint256 c = mulmod(a, b, G.GEN_ORDER);

        G.G1Point[] memory y_r = new G.G1Point[](no);
        a_poly[0] = a;
        b_poly[0] = b;
        c_poly[0] = c;
        for(uint i=1; i<to; i++){
            a_poly[i] = gen_random();
            b_poly[i] = gen_random();
            c_poly[i] = gen_random();
        }
        G.G1Point memory G1_r = G.g1mul(G.P1(), r);
        for(uint i=1; i<=no; i++){
            y_r[i-1] = G.g1mul(pub_key[i-1], r);
        }
        for(uint i=1; i<=no; i++){
            uint256 t = hash_to_int_2(y_r[i-1]);
            uint256 a1 = gen_share(a_poly,i);
            uint256 b1 = gen_share(b_poly,i);
            uint256 c1 = gen_share(c_poly,i);
            a_share[i-1] = t^a1;
            b_share[i-1] = t^b1;
            c_share[i-1] = t^c1; 
        }
        // for(uint i=0; i<no; i++){
        //     a_poly[i] = 0; b_poly[i] = 0; c_poly[i] = 0;
        //     // a_share[i] = 0; b_share[i] = 0; c_share[i] = 0;
        // }
        return G1_r;
    }

    function verify_revocation_request( string memory name, uint256 kr,  G.G1Point memory witness, G.G1Point memory H, G.G1Point memory S, G.G1Point[] memory commitments) public{
           G.G1Point[] memory r = params.get_bpk(name);
            G.G1Point memory s = gen_beaver_tuples(r);
            //G.G1Point memory s = G.P1();
            uint256[] memory ab = new uint256[](2);
            uint256[] memory a = new uint256[](2);
            uint256[] memory b = new uint256[](2);
            uint256[] memory c = new uint256[](2);
            uint256[2][] memory cm = new uint256[2][](commitments.length);
            a[0] = witness.X;
            a[1] = witness.Y;
            ab[0] = s.X;ab[1] = s.Y;
            b[0] = H.X;
            b[1] = H.Y;
            c[0] = S.X;
            c[1] = S.Y;
            for(uint i =0;i<commitments.length;i++){
                cm[i][0] = commitments[i].X;
                cm[i][1] = commitments[i].Y;
            }
            
            emit send_self_revocation(kr,a, b,c, cm,ab,a_share, b_share, c_share);

    }
    function hash_to_G1(G.G1Point memory m) public view returns (G.G1Point memory){
        uint256 cm = m.X;
        uint256 cm2 = m.Y;
        bytes32 bcm = bytes32(cm);
        bytes32 bcm2 = bytes32(cm2);
        bytes memory c = new bytes(64);
        for(uint i=0;i<32;i++){
            c[i] = bcm[i];
        }
        for(uint j=32;j<64;j++){
            c[j] = bcm2[j-32];
        }
        uint256 id = uint256(sha256(c));
        return G.HashToPoint(id);
    }

    function hash_to_int(G.G1Point memory a) public view returns(uint256){
        G.G1Point memory b = hash_to_G1(a);
        uint256 cm = b.X;
        uint256 cm2 = b.Y;
        bytes32 bcm = bytes32(cm);
        bytes32 bcm2 = bytes32(cm2);
        bytes memory c = new bytes(64);
        for(uint i=0;i<32;i++){
            c[i] = bcm[i];
        }
        for(uint j=32;j<64;j++){
            c[j] = bcm2[j-32];
        }
        uint256 id = uint256(sha256(c));
        return id;
    }

    function hash_to_int_2(G.G1Point memory a) public pure returns(uint256){
        uint256 cm = a.X;
        uint256 cm2 = a.Y;
        bytes32 bcm = bytes32(cm);
        bytes32 bcm2 = bytes32(cm2);
        bytes memory c = new bytes(64);
        for(uint i=0;i<32;i++){
            c[i] = bcm[i];
        }
        for(uint j=32;j<64;j++){
            c[j] = bcm2[j-32];
        }
        uint256 id = uint256(sha256(c));
        return id;
    }

    function recieve_ya_share(uint id, uint256 share, uint256 request_id) public {
        if(flag[request_id] == 1) return;

        accumulator_key_shares[id-1]= share;
        uint count = 0;
        for (uint i=0; i<no; i++) 
        {
            if(accumulator_key_shares[i] != 0) count++;
        }
        if(count==to){
            uint256[2] memory W = [delta.X,delta.Y];

            delta = G.g1mul(delta,aggregate_value(4));       
            for (uint i=1; i<=no; i++) 
            {
               accumulator_key_shares[i-1] = 0;
            }

            whitelist.push([id_kr[request_id],block.timestamp]);
            flag[request_id] = 1;
            emit send_W_kr(W,request_id,id_kr[request_id], block.timestamp);
            //emit send_W_kr(W_m,delta,request_id);
        }
        
    }

    function updateWitness(uint256 time) public view returns (uint256[] memory, uint256[] memory, uint256 ){
            uint256[] memory w1 = new uint256[](whitelist.length);
            uint256[] memory b1 = new uint256[](blacklist.length);
            uint c = 0;
            for(uint i = whitelist.length-1; i>=0;i--){
                if(whitelist[i][1] < time) break;
                w1[c] = whitelist[i][0];
                c++;
            }
            c = 0;
            for(uint i = blacklist.length-1; i>=0;i--){
                if(blacklist[i][1] < time) break;
                b1[c] = blacklist[i][0];
                c++;
            }
            return (w1,b1, block.timestamp);
    }
    function set_accumulator(uint _no,uint _to,uint _nv,uint _tv) public {
        delta = G.P1();
        no = _no;
        nv = _nv;
        to = _to;
        tv = _tv;
        a_poly = new uint256[](to);
        b_poly = new uint256[](to);
        c_poly = new uint256[](to);
        a_share = new uint256[](no);
        b_share = new uint256[](no);
        c_share = new uint256[](no);
        combine_di = new uint256[](no);
        combine_ei = new uint256[](no);
        combine_si = new uint256[](no);
        accumulator_key_shares = new uint256[](no);
        delta_shares = new uint256[](no);
        for (uint i=1; i<=no; i++) 
        {
            accumulator_key_shares[i-1] = 0;
            delta_shares[i-1] = 0;
            combine_di[i-1] = 0;combine_ei[i-1] = 0;combine_si[i-1] = 0;
        }
    }

    function gen_share(uint256[] memory array, uint x) public view returns(uint256){
        uint256 ans = 0;
        uint256 o = G.GEN_ORDER;
        for(uint i=0; i<array.length; i++){
            ans = addmod(ans , mulmod(array[i],G.expMod(x,i,o),o),o); 
        }
        return ans % o;
    }

    function generate_kr_shares(G.G1Point memory cm) public returns(uint256[] memory, uint256[] memory) {
        uint256[] memory poly_validators = new uint256[](tv);
        uint256[] memory poly_openers = new uint256[](to);
        uint256[] memory validators_share = new uint256[](nv);
        uint256[] memory openers_share = new uint256[](no);
        uint256 kr = gen_random();
        id_kr[hash_to_int(cm)] = kr;
        
        poly_validators[0] = kr;
        poly_openers[0] = kr;
        for(uint i=1; i<tv; i++){
            poly_validators[i] = gen_random();
        }
        for(uint i=1; i<to; i++){
            poly_openers[i] = gen_random();
        }

        for(uint i=1; i<=nv; i++){
            validators_share[i-1] = gen_share(poly_validators,i);
        }
        for(uint i=1; i<=no; i++){
            openers_share[i-1] = gen_share(poly_openers,i);
        }
        return (validators_share, openers_share);
    }

    function gen_random() private returns(uint256){
        randNonce++;
        return uint256(keccak256(abi.encodePacked(block.timestamp,msg.sender,randNonce))) % G.GEN_ORDER;
    }
}