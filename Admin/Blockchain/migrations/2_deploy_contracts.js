const fs = require('fs');
var adminAddress;
var SpAddress;
var data = fs.readFileSync('../../addresses.txt', 'utf8')
var ans = data.split("\n");
ans.forEach(element => {
      var t = element.split("=")
      if(t[0] === 'admin') adminAddress = t[1];
      if(t[0] === 'SP') SpAddress = t[1];
});

var G2 = artifacts.require("./libraries/BN256G2");
var BnCurve = artifacts.require("./libraries/G");
var Request = artifacts.require("./contracts/Request");
var Params = artifacts.require("./contracts/Params");
var Verify = artifacts.require("./contracts/Verify");
var Opening = artifacts.require("./contracts/Opening");
var Issue = artifacts.require("./contracts/Issue");
var Accumulator = artifacts.require("./contracts/Accumulator");


module.exports = async function (deployer) {

  await deployer.deploy(G2, {from: adminAddress});
  const g2 = await G2.deployed()

  await deployer.link(G2, BnCurve);
  await deployer.deploy(BnCurve, {from: adminAddress});
  const bnCurve = await BnCurve.deployed()

  await deployer.link(BnCurve, Params);
  await deployer.deploy(Params, {from: adminAddress});
  const params = await Params.deployed()

  // await Verify.detectNetwork();
  await deployer.link(BnCurve, Verify);
  await deployer.link(G2, Verify);
  await deployer.deploy(Verify, params.address, {from: SpAddress});
  const verify = await Verify.deployed()
  
  await deployer.link(G2, Accumulator);
  await deployer.deploy(Accumulator,params.address, {from: adminAddress});
  const accumulator = await Accumulator.deployed()

  await deployer.link(BnCurve, Request);
  await deployer.link(G2, Request);
  await deployer.deploy(Request, params.address,accumulator.address, {from: adminAddress});
  const request = await Request.deployed()

  await deployer.deploy(Issue, params.address, {from: adminAddress});
  const issue = await Issue.deployed()

  await deployer.deploy(Opening, params.address, {from: adminAddress});
  const opening = await Opening.deployed()

  console.log("Open "+ opening.address);
  console.log("Issue " + issue.address);
  console.log("Request "+request.address);
  console.log("Params "+ params.address);
  console.log("Verify "+ verify.address);
  console.log("Accu "+ accumulator.address)
};