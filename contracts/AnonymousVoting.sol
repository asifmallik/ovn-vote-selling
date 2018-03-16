pragma solidity ^0.4.18;

import "./Secp256k1.sol";
import "./LocalCrypto.sol";
import "./Utils.sol";

contract owned {
    address public owner;

    /* Initialise contract creator as owner */
    function owned() {
        owner = msg.sender;
    }

    /* Function to dictate that only the designated owner can call a function */
	  modifier onlyOwner {
        if(owner != msg.sender) throw;
        _;
    }

    /* Transfer ownership of this contract to someone else */
    function transferOwnership(address newOwner) onlyOwner() {
        owner = newOwner;
    }
}

/*
 * @title AnonymousVoting
 *  Open Vote Network
 *  A self-talling protocol that supports voter privacy.
 *
 *  Author: Patrick McCorry
 */
contract AnonymousVoting is owned {

  // Modulus for public keys
  uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  // Base point (generator) G
  uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

  // Modulus for private keys (sub-group)
  uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  uint[2] G;

  //Every address has an index
  //This makes looping in the program easier.
  address[] public addresses;
  mapping (address => uint) public addressid; // Address to Counter
  mapping (uint => Voter) public voters;
  mapping (address => bool) public eligible; // White list of addresses allowed to vote
  mapping (address => bool) public registered; // Address registered?
  mapping (address => bool) public votecast; // Address voted?
  mapping (address => bool) public commitment; // Have we received their commitment?
  mapping (address => uint) public refunds; // Have we received their commitment?

  struct Voter {
      address addr;
      uint[2] registeredkey;
      uint[2] reconstructedkey;
      bytes32 commitment;
      uint[2] vote;
  }

  // Work around function to fetch details about a voter
  function getVoter() returns (uint[2] _registeredkey, uint[2] _reconstructedkey, bytes32 _commitment){
      uint index = addressid[msg.sender];
      _registeredkey = voters[index].registeredkey;
      _reconstructedkey = voters[index].reconstructedkey;
      _commitment = voters[index].commitment;
  }

  function getVoterById(uint index) returns (uint[2] _registeredkey, uint[2] _reconstructedkey, uint[2] _vote){
      _registeredkey = voters[index].registeredkey;
      _reconstructedkey = voters[index].reconstructedkey;
      _vote = voters[index].vote;
  }

  // List of timers that each phase MUST end by an explicit time in UNIX timestamp.
  // Ethereum works in SECONDS. Not milliseconds.
  uint public finishSignupPhase; // Election Authority to transition to next phase.
  uint public endSignupPhase; // Election Authority does not transition to next phase by this time.
  uint public endCommitmentPhase; // Voters have not sent their commitments in by this time.
  uint public endVotingPhase; // Voters have not submitted their vote by this stage.
  uint public endRefundPhase; // Voters must claim their refund by this stage.

  uint public totalregistered; //Total number of participants that have submited a voting key
  uint public totaleligible;
  uint public totalcommitted;
  uint public totalvoted;
  uint public totalrefunded;
  uint public totaltorefund;

  string public question;
  uint[2] public finaltally; // Final tally
  bool public commitmentphase; // OPTIONAL phase.
  uint public depositrequired;
  uint public gap; // Minimum amount of time between time stamps.
  address public charity;

  // TODO: Why cant election authority receive the spoils?
  uint public lostdeposit; // This money is collected from non active voters...

  enum State { SETUP, SIGNUP, COMMITMENT, VOTE, FINISHED }
  State public state;

  modifier inState(State s) {
    if(state != s) {
        throw;
    }
    _;
  }

  // 2 round anonymous voting protocol
  // TODO: Right now due to gas limits there is an upper limit
  // on the number of participants that we can have voting...
  // I need to split the functions up... so if they cannot
  // finish their entire workload in 1 transaction, then
  // it does the maximum. This way we can chain transactions
  // to complete the job...
  function AnonymousVoting(uint _gap, address _charity) {
    G[0] = Gx;
    G[1] = Gy;
    state = State.SETUP;
    question = "No question set";
    gap = _gap; // Minimum gap period between stages
    charity = _charity;
  }

  // Owner of contract sets a whitelist of addresses that are eligible to vote.
  function setEligible(address[] addr) onlyOwner {

    // We can only handle up 50 people at the moment.
    if(totaleligible > 50) {
      throw;
    }

    // Sign up the addresses
    for(uint i=0; i<addr.length; i++) {

      if(!eligible[addr[i]]) {
        eligible[addr[i]] = true;
        addresses.push(addr[i]);
        totaleligible += 1;
      }
    }
  }

  // Owner of contract declares that eligible addresses begin round 1 of the protocol
  // Time is the number of 'blocks' we must wait until we can move onto round 2.
  function beginSignUp(string _question, bool enableCommitmentPhase, uint _finishSignupPhase, uint _endSignupPhase, uint _endCommitmentPhase, uint _endVotingPhase, uint _endRefundPhase, uint _depositrequired) inState(State.SETUP) onlyOwner payable returns (bool){

    // We have lots of timers. let's explain each one
    // _finishSignUpPhase - Voters should be signed up before this timer

    // Voter is refunded if any of the timers expire:
    // _endSignUpPhase - Election Authority never finished sign up phase
    // _endCommitmentPhase - One or more voters did not send their commitments in time
    // _endVotingPhase - One or more voters did not send their votes in time
    // _endRefundPhase - Provide time for voters to get their money back.
    // Why is there no endTally? Because anyone can call it!

    // Represented in UNIX time...
    // TODO: Set to block timestamp...
    // TODO: Enforce gap to be at least 1 hour.. may break unit testing
    // Make sure 3 people are at least eligible to vote..
    // Deposit can be zero or more WEI
    if(_finishSignupPhase > 0 + gap && addresses.length >= 3 && _depositrequired >= 0) {

        // Ensure each time phase finishes in the future...
        // Ensure there is a gap of 'x time' between each phase.
        if(_endSignupPhase-gap < _finishSignupPhase) {
          return false;
        }

        // We need to check Commitment timestamps if phase is enabled.
        if(enableCommitmentPhase) {

          // Make sure there is a gap between 'end of registration' and 'end of commitment' phases.
          if(_endCommitmentPhase-gap < _endSignupPhase) {
            return false;
          }

          // Make sure there is a gap between 'end of commitment' and 'end of vote' phases.
          if(_endVotingPhase-gap < _endCommitmentPhase) {
            return false;
          }

        } else {

          // We have no commitment phase.
          // Make sure there is a gap between 'end of registration' and 'end of vote' phases.
          if(_endVotingPhase-gap < _endSignupPhase) {
            return false;
          }
        }

        // Provide time for people to get a refund once the voting phase has ended.
        if(_endRefundPhase-gap < _endVotingPhase) {
          return false;
        }


      // Require Election Authority to deposit ether.
      if(msg.value  != _depositrequired) {
        return false;
      }

      // Store the election authority's deposit
      // Note: This deposit is only lost if the
      // election authority does not begin the election
      // or call the tally function before the timers expire.
      refunds[msg.sender] = msg.value;

      // All time stamps are reasonable.
      // We can now begin the signup phase.
      state = State.SIGNUP;

      // All timestamps should be in UNIX..
      finishSignupPhase = _finishSignupPhase;
      endSignupPhase = _endSignupPhase;
      endCommitmentPhase = _endCommitmentPhase;
      endVotingPhase = _endVotingPhase;
      endRefundPhase = _endRefundPhase;
      question = _question;
      commitmentphase = enableCommitmentPhase;
      depositrequired = _depositrequired; // Deposit required from all voters

      return true;
    }

    return false;
  }

  // This function determines if one of the deadlines have been missed
  // If a deadline has been missed - then we finish the election,
  // and allocate refunds to the correct people depending on the situation.
  function deadlinePassed() returns (bool){

      uint refund = 0;

      // Has the Election Authority missed the signup deadline?
      // Election Authority will forfeit his deposit.
      if(state == State.SIGNUP && block.timestamp > endSignupPhase) {

         // Nothing to do. All voters are refunded.
         state = State.FINISHED;
         totaltorefund = totalregistered;

         // Election Authority forfeits his deposit...
         // If 3 or more voters had signed up...
         if(addresses.length >= 3) {
           // Election Authority forfeits deposit
           refund = refunds[owner];
           refunds[owner] = 0;
           lostdeposit = lostdeposit + refund;

         }
         return true;
      }

      // Has a voter failed to send their commitment?
      // Election Authority DOES NOT forgeit his deposit.
      if(state == State.COMMITMENT && block.timestamp > endCommitmentPhase) {

         // Check which voters have not sent their commitment
         for(uint i=0; i<totalregistered; i++) {

            // Voters forfeit their deposit if failed to send a commitment
            if(!commitment[voters[i].addr]) {
               refund = refunds[voters[i].addr];
               refunds[voters[i].addr] = 0;
               lostdeposit = lostdeposit + refund;
            } else {

              // We will need to refund this person.
              totaltorefund = totaltorefund + 1;
            }
         }

         state = State.FINISHED;
         return true;
      }

      // Has a voter failed to send in their vote?
      // Eletion Authority does NOT forfeit his deposit.
      if(state == State.VOTE && block.timestamp > endVotingPhase) {

         // Check which voters have not cast their vote
         for(i=0; i<totalregistered; i++) {

            // Voter forfeits deposit if they have not voted.
            if(!votecast[voters[i].addr]) {
              refund = refunds[voters[i].addr];
              refunds[voters[i].addr] = 0;
              lostdeposit = lostdeposit + refund;
            } else {

              // Lets make sure refund has not already been issued...
              if(refunds[voters[i].addr] > 0) {
                // We will need to refund this person.
                totaltorefund = totaltorefund + 1;
              }
            }
         }

         state = State.FINISHED;
         return true;
      }

      // Has the deadline passed for voters to claim their refund?
      // Only owner can call. Owner must be refunded (or forfeited).
      // Refund period is over or everyone has already been refunded.
      if(state == State.FINISHED && msg.sender == owner && refunds[owner] == 0 && (block.timestamp > endRefundPhase || totaltorefund == totalrefunded)) {

         // Collect all unclaimed refunds. We will send it to charity.
         for(i=0; i<totalregistered; i++) {
           refund = refunds[voters[i].addr];
           refunds[voters[i].addr] = 0;
           lostdeposit = lostdeposit + refund;
         }

         uint[2] memory empty;

         for(i=0; i<addresses.length; i++) {
            address addr = addresses[i];
            eligible[addr] = false; // No longer eligible
            registered[addr] = false; // Remove voting registration
            voters[i] = Voter({addr: 0, registeredkey: empty, reconstructedkey: empty, vote: empty, commitment: 0});
            addressid[addr] = 0; // Remove index
            votecast[addr] = false; // Remove that vote was cast
            commitment[addr] = false;
         }

         // Reset timers.
         finishSignupPhase = 0;
         endSignupPhase = 0;
         endCommitmentPhase = 0;
         endVotingPhase = 0;
         endRefundPhase = 0;

         delete addresses;

         // Keep track of voter activity
         totalregistered = 0;
         totaleligible = 0;
         totalcommitted = 0;
         totalvoted = 0;

         // General values that need reset
         question = "No question set";
         finaltally[0] = 0;
         finaltally[1] = 0;
         commitmentphase = false;
         depositrequired = 0;
         totalrefunded = 0;
         totaltorefund = 0;

         state = State.SETUP;
         return true;
      }

      // No deadlines have passed...
      return false;
  }

  // Called by participants to register their voting public key
  // Participant mut be eligible, and can only register the first key sent key.
  function register(uint[2] xG, uint[3] vG, uint r) inState(State.SIGNUP) payable returns (bool) {

     // HARD DEADLINE
     if(block.timestamp > finishSignupPhase) {
       throw; // throw returns the voter's ether, but exhausts their gas.
     }

    // Make sure the ether being deposited matches what we expect.
    if(msg.value != depositrequired) {
      return false;
    }

    // Only white-listed addresses can vote
    if(eligible[msg.sender]) {
        if(Utils.verifyZKP(xG,r,vG) && !registered[msg.sender]) {

            // Store deposit
            refunds[msg.sender] = msg.value;

            // Update voter's registration
            uint[2] memory empty;
            addressid[msg.sender] = totalregistered;
            voters[totalregistered] = Voter({addr: msg.sender, registeredkey: xG, reconstructedkey: empty, vote: empty, commitment: 0});
            registered[msg.sender] = true;
            totalregistered += 1;

            return true;
        }
    }

    return false;
  }


  // Timer has expired - we want to start computing the reconstructed keys
  function finishRegistrationPhase() inState(State.SIGNUP) onlyOwner returns(bool) {


      // Make sure at least 3 people have signed up...
      if(totalregistered < 3) {
        return;
      }

      // We can only compute the public keys once participants
      // have been given an opportunity to register their
      // voting public key.
      if(block.timestamp < finishSignupPhase) {
        return;
      }

      // Election Authority has a deadline to begin election
      if(block.timestamp > endSignupPhase) {
        return;
      }

      uint[2] memory temp;
      uint[3] memory yG;
      uint[3] memory beforei;
      uint[3] memory afteri;

      // Step 1 is to compute the index 1 reconstructed key
      afteri[0] = voters[1].registeredkey[0];
      afteri[1] = voters[1].registeredkey[1];
      afteri[2] = 1;

      for(uint i=2; i<totalregistered; i++) {
         Secp256k1._addMixedM(afteri, voters[i].registeredkey);
      }

      ECCMath.toZ1(afteri,pp);
      voters[0].reconstructedkey[0] = afteri[0];
      voters[0].reconstructedkey[1] = pp - afteri[1];

      // Step 2 is to add to beforei, and subtract from afteri.
     for(i=1; i<totalregistered; i++) {

       if(i==1) {
         beforei[0] = voters[0].registeredkey[0];
         beforei[1] = voters[0].registeredkey[1];
         beforei[2] = 1;
       } else {
         Secp256k1._addMixedM(beforei, voters[i-1].registeredkey);
       }

       // If we have reached the end... just store beforei
       // Otherwise, we need to compute a key.
       // Counting from 0 to n-1...
       if(i==(totalregistered-1)) {
         ECCMath.toZ1(beforei,pp);
         voters[i].reconstructedkey[0] = beforei[0];
         voters[i].reconstructedkey[1] = beforei[1];

       } else {

          // Subtract 'i' from afteri
          temp[0] = voters[i].registeredkey[0];
          temp[1] = pp - voters[i].registeredkey[1];

          // Grab negation of afteri (did not seem to work with Jacob co-ordinates)
          Secp256k1._addMixedM(afteri,temp);
          ECCMath.toZ1(afteri,pp);

          temp[0] = afteri[0];
          temp[1] = pp - afteri[1];

          // Now we do beforei - afteri...
          yG = Secp256k1._addMixed(beforei, temp);

          ECCMath.toZ1(yG,pp);

          voters[i].reconstructedkey[0] = yG[0];
          voters[i].reconstructedkey[1] = yG[1];
       }
     }

      // We have computed each voter's special voting key.
      // Now we either enter the commitment phase (option) or voting phase.
      if(commitmentphase) {
        state = State.COMMITMENT;
      } else {
        state = State.VOTE;
      }
  }

  /*
   * OPTIONAL STAGE: All voters submit the hash of their vote.
   * Why? The final voter that submits their vote gets to see the tally result
   * before anyone else. This provides the voter with an additional advantage
   * compared to all other voters. To get around this issue; we can force all
   * voters to commit to their vote in advance.... and votes are only revealed
   * once all voters have committed. This way the final voter has no additional
   * advantage as they cannot change their vote depending on the tally.
   * However... we cannot enforce the pre-image to be a hash, and someone could
   * a commitment that is not a vote. This will break the election, but you
   * will be able to determine who did it (and possibly punish them!).
   */
  function submitCommitment(bytes32 h) inState(State.COMMITMENT) {

     //All voters have a deadline to send their commitment
     if(block.timestamp > endCommitmentPhase) {
       return;
     }

    if(!commitment[msg.sender]) {
        commitment[msg.sender] = true;
        uint index = addressid[msg.sender];
        voters[index].commitment = h;
        totalcommitted = totalcommitted + 1;

        // Once we have recorded all commitments... let voters vote!
        if(totalcommitted == totalregistered) {
          state = State.VOTE;
        }
    }
  }

  // Given the 1 out of 2 ZKP - record the users vote!
  function submitVote(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) inState(State.VOTE) returns (bool) {

     // HARD DEADLINE
     if(block.timestamp > endVotingPhase) {
       return;
     }

     uint c = addressid[msg.sender];

     // Make sure the sender can vote, and hasn't already voted.
     if(registered[msg.sender] && !votecast[msg.sender]) {

       // OPTIONAL Phase: Voters need to commit to their vote in advance.
       // Time to verify if this vote matches the voter's previous commitment.
       if(commitmentphase) {

         // Voter has previously committed to the entire zero knowledge proof...
         bytes32 h = sha3(msg.sender, params, voters[c].registeredkey, voters[c].reconstructedkey, y, a1, b1, a2, b2);

         // No point verifying the ZKP if it doesn't match the voter's commitment.
         if(voters[c].commitment != h) {
           return false;
         }
       }

       // Verify the ZKP for the vote being cast
       uint i = addressid[msg.sender];
       if(Utils.verify1outof2ZKP(params, voters[i].registeredkey, voters[i].reconstructedkey, y, a1, b1, a2, b2)) {
         voters[c].vote[0] = y[0];
         voters[c].vote[1] = y[1];

         votecast[msg.sender] = true;

         totalvoted += 1;

         // Refund the sender their ether..
         // Voter has finished their part of the protocol...
         uint refund = refunds[msg.sender];
         refunds[msg.sender] = 0;

         // We can still fail... Safety first.
         // If failed... voter can call withdrawRefund()
         // to collect their money once the election has finished.
         if (!msg.sender.send(refund)) {
            refunds[msg.sender] = refund;
         }

         return true;
       }
     }

     // Either vote has already been cast, or ZKP verification failed.
     return false;
  }

  // Assuming all votes have been submitted. We can leak the tally.
  // We assume Election Authority performs this function. It could be anyone.
  // Election Authority gets deposit upon tallying.
  // TODO: Anyone can do this function. Perhaps remove refund code - and force Election Authority
  // to explicit withdraw it? Election cannot reset until he is refunded - so that should be OK
  function computeTally() inState(State.VOTE) onlyOwner {

     uint[3] memory temp;
     uint[2] memory vote;
     uint refund;

     // Sum all votes
     for(uint i=0; i<totalregistered; i++) {

         // Confirm all votes have been cast...
         if(!votecast[voters[i].addr]) {
            throw;
         }

         vote = voters[i].vote;

         if(i==0) {
           temp[0] = vote[0];
           temp[1] = vote[1];
           temp[2] = 1;
         } else {
             Secp256k1._addMixedM(temp, vote);
         }
     }

     // All votes have been accounted for...
     // Get tally, and change state to 'Finished'
     state = State.FINISHED;

     // All voters should already be refunded!
     for(i = 0; i<totalregistered; i++) {

       // Sanity check.. make sure refunds have been issued..
       if(refunds[voters[i].addr] > 0) {
         totaltorefund = totaltorefund + 1;
       }
     }

     // Each vote is represented by a G.
     // If there are no votes... then it is 0G = (0,0)...
     if(temp[0] == 0) {
       finaltally[0] = 0;
       finaltally[1] = totalregistered;

       // Election Authority is responsible for calling this....
       // He should not fail his own refund...
       // Make sure tally is computed before refunding...
       // TODO: Check if this is necessary
       refund = refunds[msg.sender];
       refunds[msg.sender] = 0;

       if (!msg.sender.send(refund)) {
          refunds[msg.sender] = refund;
       }
       return;
     } else {

       // There must be a vote. So lets
       // start adding 'G' until we
       // find the result.
       ECCMath.toZ1(temp,pp);
       uint[3] memory tempG;
       tempG[0] = G[0];
       tempG[1] = G[1];
       tempG[2] = 1;

       // Start adding 'G' and looking for a match
       for(i=1; i<=totalregistered; i++) {

         if(temp[0] == tempG[0]) {
             finaltally[0] = i;
             finaltally[1] = totalregistered;

             // Election Authority is responsible for calling this....
             // He should not fail his own refund...
             // Make sure tally is computed before refunding...
             // TODO: Check if this is necessary
             // If it fails - he can use withdrawRefund()
             // Election cannot be reset until he is refunded.
             refund = refunds[msg.sender];
             refunds[msg.sender] = 0;

             if (!msg.sender.send(refund)) {
                refunds[msg.sender] = refund;
             }
             return;
         }

         // If something bad happens and we cannot find the Tally
         // Then this 'addition' will be run 1 extra time due to how
         // we have structured the for loop.
         // TODO: Does it need fixed?
         Secp256k1._addMixedM(tempG, G);
           ECCMath.toZ1(tempG,pp);
         }

         // Something bad happened. We should never get here....
         // This represents an error message... best telling people
         // As we cannot recover from it anyway.
         // TODO: Handle this better....
         finaltally[0] = 0;
         finaltally[1] = 0;

         // Election Authority is responsible for calling this....
         // He should not fail his own refund...
         // TODO: Check if this is necessary
         refund = refunds[msg.sender];
         refunds[msg.sender] = 0;

         if (!msg.sender.send(refund)) {
            refunds[msg.sender] = refund;
         }
         return;
      }
  }

  // There are two reasons why we might be in a finished state
  // 1. The tally has been computed
  // 2. A deadline has been missed.
  // In the former; everyone gets a refund. In the latter; only active participants get a refund
  // We can assume if the deadline has been missed - then refunds has ALREADY been updated to
  // take that into account. (a transaction is required to indicate a deadline has been missed
  // and in that transaction - we can penalise the non-active participants. lazy sods!)
  function withdrawRefund() inState(State.FINISHED){

    uint refund = refunds[msg.sender];
    refunds[msg.sender] = 0;

    if (!msg.sender.send(refund)) {
       refunds[msg.sender] = refund;
    } else {

      // Tell everyone we have issued the refund.
      // Owner is not included in refund counter.
      // This is OK - we cannot reset election until
      // the owner has been refunded...
      // Counter only concerns voters!
      if(msg.sender != owner) {
         totalrefunded = totalrefunded + 1;
      }
    }
  }

  // Send the lost deposits to a charity. Anyone can call it.
  // Lost Deposit increments for each failed election. It is only
  // reset upon sending to the charity!
  function sendToCharity() {

    // Only send this money to the owner
    uint profit = lostdeposit;
    lostdeposit = 0;

    // Try to send money
    if(!charity.send(profit)) {

      // We failed to send the money. Record it again.
      lostdeposit = profit;
    }
  }
}
