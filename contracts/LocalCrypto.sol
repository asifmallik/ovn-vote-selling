pragma solidity ^0.4.18;

import "./Secp256k1.sol";
import "./Utils.sol";

/*
 * @title LocalCrypto
 * Allow local calls to create and verify zkp.
 *  Author: Patrick McCorry
 */
contract LocalCrypto {

  // Modulus for public keys
  uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  // Base point (generator) G
  uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

  // New  point (generator) Y
  uint constant Yx = 98038005178408974007512590727651089955354106077095278304532603697039577112780;
  uint constant Yy = 1801119347122147381158502909947365828020117721497557484744596940174906898953;

  // Modulus for private keys (sub-group)
  uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  uint[2] G;
  uint[2] Y;

  event Debug(uint x1, uint x2);

  // 2 round anonymous voting protocol
  // TODO: Right now due to gas limits there is an upper limit
  // on the number of participants that we can have voting...
  // I need to split the functions up... so if they cannot
  // finish their entire workload in 1 transaction, then
  // it does the maximum. This way we can chain transactions
  // to complete the job...
  function LocalCrypto() {
    G[0] = Gx;
    G[1] = Gy;

    Y[0] = Yx;
    Y[1] = Yy;
  }


  // Retrieve the commitment hash for a voters vote.
  function commitToVote(uint[4] params, uint[2] xG, uint[2] yG, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bytes32) {
    return sha3(msg.sender, params, xG, yG, y, a1, b1, a2, b2);
  }

  // vG (blinding value), xG (public key), x (what we are proving)
  // c = H(g, g^{v}, g^{x});
  // r = v - xz (mod p);
  // return(r,vG)
  function createZKP(uint x, uint v, uint[2] xG) returns (uint[4] res) {

      uint[2] memory G;
      G[0] = Gx;
      G[1] = Gy;

      if(!Secp256k1.isPubKey(xG)) {
          throw; //Must be on the curve!
      }

      // Get g^{v}
      uint[3] memory vG = Secp256k1._mul(v, G);

      // Convert to Affine Co-ordinates
      ECCMath.toZ1(vG, pp);

      // Get c = H(g, g^{x}, g^{v});
      bytes32 b_c = sha256(msg.sender, Gx, Gy, xG, vG);
      uint c = uint(b_c);

      // Get 'r' the zkp
      uint xc = mulmod(x,c,nn);

      // v - xc
      uint r = submod(v,xc);

      res[0] = r;
      res[1] = vG[0];
      res[2] = vG[1];
      res[3] = vG[2];
      return;
  }

  // a - b = c;
  function submod(uint a, uint b) returns (uint){
      uint a_nn;

      if(a>b) {
        a_nn = a;
      } else {
        a_nn = a+nn;
      }

      uint c = addmod(a_nn - b,0,nn);

      return c;
  }

  // Parameters xG, r where r = v - xc, and vG.
  // Verify that vG = rG + xcG!
  function verifyZKP(uint[2] xG, uint r, uint[3] vG) returns (bool){
      return Utils.verifyZKP(xG, r, vG);
  }

  // random 'w', 'r1', 'd1'
  function create1outof2ZKPNoVote(uint[2] xG, uint[2] yG, uint w, uint r2, uint d2, uint x) returns (uint[10] res, uint[4] res2){
      uint[2] memory temp_affine1;
      uint[2] memory temp_affine2;

      // y = h^{x} * g
      uint[3] memory temp1 = Secp256k1._mul(x,yG);
      ECCMath.toZ1(temp1, pp);

      // Store y_x and y_y
      res[0] = temp1[0];
      res[1] = temp1[1];

      // a1 = g^{w}
      temp1 = Secp256k1._mul(w,G);
      ECCMath.toZ1(temp1, pp);

      // Store a1_x and a1_y
      res[2] = temp1[0];
      res[3] = temp1[1];

      // b1 = h^{w} (where h = g^{y})
      temp1 = Secp256k1._mul(w, yG);
      ECCMath.toZ1(temp1, pp);

      res[4] = temp1[0];
      res[5] = temp1[1];

      // a2 = g^{r2} * x^{d2}
      temp1 = Secp256k1._mul(r2,G);
      temp1 = Secp256k1._add(temp1, Secp256k1._mul(d2,xG));
      ECCMath.toZ1(temp1, pp);

      res[6] = temp1[0];
      res[7] = temp1[1];

      // Negate the 'y' co-ordinate of G
      temp_affine1[0] = G[0];
      temp_affine1[1] = pp - G[1];

      // We need the public key y in affine co-ordinates
      temp_affine2[0] = res[0];
      temp_affine2[1] = res[1];

      // We should end up with y^{d2} + g^{d2} .... (but we have the negation of g.. so y-g).
      temp1 = Secp256k1._add(Secp256k1._mul(d2,temp_affine2), Secp256k1._mul(d2,temp_affine1));

      // Now... it is h^{r2} + temp2..
      temp1 = Secp256k1._add(Secp256k1._mul(r2,yG),temp1);

      // Convert to Affine Co-ordinates
      ECCMath.toZ1(temp1, pp);

      res[8] = temp1[0];
      res[9] = temp1[1];

      // Get c = H(i, xG, Y, a1, b1, a2, b2);
      bytes32 b_c = sha256(msg.sender, xG, res);

      // d1 = c - d2 mod q
      temp1[0] = submod(uint(b_c),d2);

      // r1 = w - (x * d1)
      temp1[1] = submod(w, mulmod(x,temp1[0],nn));

      /* We return the following
      * res[0] = y_x;
      * res[1] = y_y;
      * res[2] = a1_x;
      * res[3] = a1_y;
      * res[4] = b1_x;
      * res[5] = b1_y;
      * res[6] = a2_x;
      * res[7] = a2_y;
      * res[8] = b2_x;
      * res[9] = b2_y;
      * res[10] = d1;
      * res[11] = d2;
      * res[12] = r1;
      * res[13] = r2;
      */
      res2[0] = temp1[0];
      res2[1] = d2;
      res2[2] = temp1[1];
      res2[3] = r2;
  }

  // random 'w', 'r1', 'd1'
  // TODO: Make constant
  function create1outof2ZKPYesVote(uint[2] xG, uint[2] yG, uint w, uint r1, uint d1, uint x) returns (uint[10] res, uint[4] res2) {
      // y = h^{x} * g
      uint[3] memory temp1 = Secp256k1._mul(x,yG);
      Secp256k1._addMixedM(temp1,G);
      ECCMath.toZ1(temp1, pp);
      res[0] = temp1[0];
      res[1] = temp1[1];

      // a1 = g^{r1} * x^{d1}
      temp1 = Secp256k1._mul(r1,G);
      temp1 = Secp256k1._add(temp1, Secp256k1._mul(d1,xG));
      ECCMath.toZ1(temp1, pp);
      res[2] = temp1[0];
      res[3] = temp1[1];

      // b1 = h^{r1} * y^{d1} (temp = affine 'y')
      temp1 = Secp256k1._mul(r1,yG);

      // Setting temp to 'y'
      uint[2] memory temp;
      temp[0] = res[0];
      temp[1] = res[1];

      temp1= Secp256k1._add(temp1, Secp256k1._mul(d1, temp));
      ECCMath.toZ1(temp1, pp);
      res[4] = temp1[0];
      res[5] = temp1[1];

      // a2 = g^{w}
      temp1 = Secp256k1._mul(w,G);
      ECCMath.toZ1(temp1, pp);

      res[6] = temp1[0];
      res[7] = temp1[1];

      // b2 = h^{w} (where h = g^{y})
      temp1 = Secp256k1._mul(w, yG);
      ECCMath.toZ1(temp1, pp);
      res[8] = temp1[0];
      res[9] = temp1[1];

      // Get c = H(id, xG, Y, a1, b1, a2, b2);
      // id is H(round, voter_index, voter_address, contract_address)...
      bytes32 b_c = sha256(msg.sender, xG, res);
      uint c = uint(b_c);

      // d2 = c - d1 mod q
      temp[0] = submod(c,d1);

      // r2 = w - (x * d2)
      temp[1] = submod(w, mulmod(x,temp[0],nn));

      /* We return the following
      * res[0] = y_x;
      * res[1] = y_y;
      * res[2] = a1_x;
      * res[3] = a1_y;
      * res[4] = b1_x;
      * res[5] = b1_y;
      * res[6] = a2_x;
      * res[7] = a2_y;
      * res[8] = b2_x;
      * res[9] = b2_y;
      * res[10] = d1;
      * res[11] = d2;
      * res[12] = r1;
      * res[13] = r2;
      */
      res2[0] = d1;
      res2[1] = temp[0];
      res2[2] = r1;
      res2[3] = temp[1];
  }

  // We verify that the ZKP is of 0 or 1.
  function verify1outof2ZKP(uint[4] params, uint[2] xG, uint[2] yG, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
      return Utils.verify1outof2ZKP(params, xG, yG, y, a1, b1, a2, b2);
    }

    // Expects random factor 'r' and commitment 'b'. Generators are hard-coded into this contract.
    function createCommitment(uint r, uint b) returns (uint[2]){

      uint[3] memory bG = Secp256k1._mul(b,G);

      uint[3] memory rY = Secp256k1._mul(r,Y);

      uint[3] memory c = Secp256k1._add(bG,rY);

      ECCMath.toZ1(c, pp);

      uint[2] memory c_affine;
      c_affine[0] = c[0];
      c_affine[1] = c[1];

      // Sanity check that everything worked as expected.
      if(!Secp256k1.isPubKey(c_affine)) {
          throw; //Must be on the curve!
      }

      return c_affine;
    }

    // We need to re-create the commitment and check that it matches c.
    function openCommitment(uint[2] c, uint r, uint b) returns (bool) {

      uint[2] memory c_computed = createCommitment(r,b);

      // Check that the commitments match...
      if(c[0] == c_computed[0] && c[1] == c_computed[1]) {
        return true;
      }

      return false;
    }

    // Equality of commitments...
    // 1. Compute t = r3*Y
    // 2. Compute h = H(ID, G, Y, C1, C2, t), where G,Y are generators, C1, C2 are both commitments, and t is random factor.
    // 3. Compute n = h*(r1,r2) + r3.
    // return t,n.
    function createEqualityProof(uint r1, uint r2, uint r3, uint[2] c1, uint[2] c2) returns (uint[2] t, uint n) {

      if(!Secp256k1.isPubKey(c1)) {
          throw; //Must be on the curve!
      }

      if(!Secp256k1.isPubKey(c2)) {
          throw; //Must be on the curve!
      }

      uint[3] memory r3Y = Secp256k1._mul(r3,Y);
      ECCMath.toZ1(r3Y, pp);

      t[0] = r3Y[0];
      t[1] = r3Y[1];

      // TODO: add msg.sender
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t));

      uint subr1r2 = submod(r1, r2);
      uint modrh = mulmod(subr1r2,h,nn);
      n = addmod(modrh,r3,nn);
    }

    // We compute h*(c1-c2) + t
    function computeFirstHalfEquality(uint[2] c1, uint[2] c2, uint h, uint[2] t) returns (uint[2] left){

      uint[3] memory negative_c2;
      // Negate the 'y' co-ordinate of C2
      negative_c2[0] = c2[0];
      negative_c2[1] = pp - c2[1];
      negative_c2[2] = 1;

      // c1 - c2
      uint[3] memory added_commitments_jacob = Secp256k1._addMixed(negative_c2,c1);

      // convert to affine points
      ECCMath.toZ1(added_commitments_jacob,pp);
      uint[2] memory added_commitments;
      added_commitments[0] = added_commitments_jacob[0];
      added_commitments[1] = added_commitments_jacob[1];

      // h*(c1-c2) + t
      uint[3] memory left_jacob = Secp256k1._addMixed(Secp256k1._mul(h,added_commitments),t);
      ECCMath.toZ1(left_jacob,pp);
      left[0] = left_jacob[0];
      left[1] = left_jacob[1];


    }

    // Verify equality proof of two pedersen commitments
    // 1. Compute h = H(ID, G, Y, C1, C2, t), where G,Y are generators, C1, C2 are both commitments, and t is random factor.
    // 2. Does nY == h*(c1-c2) + t
    function verifyEqualityProof(uint n,  uint[2] c1, uint[2] c2, uint[2] t) returns (bool) {
      if(!Secp256k1.isPubKey(c1)) { throw; }
      if(!Secp256k1.isPubKey(c2)) { throw; }
      if(!Secp256k1.isPubKey(t)) { throw; }

      // Time to start trying to verify it... will be moved to another function
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t));

      uint[2] memory left = computeFirstHalfEquality(c1,c2,h,t);

      // n * Y
      uint[3] memory right = Secp256k1._mul(n,Y);

      ECCMath.toZ1(right, pp);

      if(left[0] == right[0] && left[1] == right[1]) {
        return true;
      } else {
        return false;
      }
    }

    // Create inequality of commitments...
    // 1. t1 = r3*G, t2 = r4*Y
    // 2. Compute h = H(ID, G, Y, c1, c2, t1, t2), where G,Y generators, c1,c2 commitments, t1,t2 inequality proof
    // 3. n1 = h*(b1-b2) + r3, n2 = h*(r1-r2) + r4.
    // return random factors t1,t2 and proofs n1,n2.
    function createInequalityProof(uint b1, uint b2, uint r1, uint r2, uint r3, uint r4, uint[2] c1, uint[2] c2) returns (uint[2] t1, uint[2] t2, uint n1, uint n2) {

      if(!Secp256k1.isPubKey(c1)) { throw; }
      if(!Secp256k1.isPubKey(c2)) { throw; }

      // r3 * G
      uint[3] memory temp = Secp256k1._mul(r3,G);
      ECCMath.toZ1(temp, pp);
      t1[0] = temp[0];
      t1[1] = temp[1];

      // r4 * Y
      temp = Secp256k1._mul(r4,Y);
      ECCMath.toZ1(temp, pp);
      t2[0] = temp[0];
      t2[1] = temp[1];

      // TODO: add msg.sender
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t1, t2));

      // h(b1-b2) + r3
      n1 = submod(b1,b2);
      uint helper = mulmod(n1,h,nn);
      n1 = addmod(helper,r3,nn);

      // h(r1-r2) + r4
      n2 = submod(r1,r2);
      helper = mulmod(n2,h,nn);
      n2 = addmod(helper,r4,nn);

    }

    // We are computing h(c1 - c2) + t2
    function computeSecondHalfInequality(uint[2] c1, uint[2] c2, uint[2] t2, uint h) returns (uint[3] right) {
      uint[3] memory negative_c2;
      // Negate the 'y' co-ordinate of C2
      negative_c2[0] = c2[0];
      negative_c2[1] = pp - c2[1];
      negative_c2[2] = 1;

      // c1 - c2
      uint[3] memory added_commitments_jacob = Secp256k1._addMixed(negative_c2,c1);

      // convert to affine points
      ECCMath.toZ1(added_commitments_jacob,pp);
      uint[2] memory added_commitments;
      added_commitments[0] = added_commitments_jacob[0];
      added_commitments[1] = added_commitments_jacob[1];

      // h(c1-c2)
      uint[3] memory h_mul_c1c2 = Secp256k1._mul(h,added_commitments);

      // right hand side h(c1-c2) + t2
      right = Secp256k1._addMixed(h_mul_c1c2,t2);
      ECCMath.toZ1(right,pp);

    }

    // Verify inequality of commitments
    // 1. Compute h = H(ID, G, Y, c1, c2, t1, t2), where G,Y generators, c1,c2 commitments, t1,t2 inequality proof
    // 2. Verify n1G + n2Y = h*(c1-c2) + t1 + t2
    // 3. Verify n2Y != h*(c1-c2) + t2
    function verifyInequalityProof(uint[2] c1, uint[2] c2, uint[2] t1, uint[2] t2, uint n1, uint n2) returns (bool) {
      if(!Secp256k1.isPubKey(c1)) { throw; }
      if(!Secp256k1.isPubKey(c2)) { throw; }
      if(!Secp256k1.isPubKey(t1)) { throw; }
      if(!Secp256k1.isPubKey(t2)) { throw; }

      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t1, t2));

      // h(c1 - c2) + t2
      uint[3] memory right = computeSecondHalfInequality(c1, c2, t2, h);

      // n2 * Y
      uint[3] memory n2Y = Secp256k1._mul(n2,Y);
      ECCMath.toZ1(n2Y,pp); // convert to affine

      if(n2Y[0] != right[0] && n2Y[1] != right[1]) {

        // h(c1 - c2) + t2 + t1
        uint[3] memory h_c1c2_t2_t1 = Secp256k1._addMixed(right, t1);
        ECCMath.toZ1(h_c1c2_t2_t1,pp); // convert to affine
        right[0] = h_c1c2_t2_t1[0];
        right[1] = h_c1c2_t2_t1[1];

        // n1G + n2Y
        uint[3] memory n1Gn2Y = Secp256k1._add(Secp256k1._mul(n1, G),n2Y);
        ECCMath.toZ1(n1Gn2Y,pp); // convert to affine

        if(n1Gn2Y[0] == right[0] && n1Gn2Y[1] == right[1]) {
          return true;
        }
      }

      return false;
    }

}
