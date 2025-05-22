// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {DeployLevelOne} from "../script/DeployLevelOne.s.sol";
import {GraduateToLevelTwo} from "../script/GraduateToLevelTwo.s.sol";
import {LevelOne} from "../src/LevelOne.sol";
import {LevelTwo} from "../src/LevelTwo.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";

contract LevelOneAndGraduateTest is Test {
    DeployLevelOne deployBot;
    GraduateToLevelTwo graduateBot;

    LevelOne levelOneProxy;
    LevelTwo levelTwoImplementation;

    address proxyAddress;
    address levelOneImplementationAddress;
    address levelTwoImplementationAddress;

    MockUSDC usdc;

    address principal;
    uint256 schoolFees;

    // teachers
    address alice;
    address bob;
    // students
    address clara;
    address dan;
    address eli;
    address fin;
    address grey;
    address harriet;

    function setUp() public {
        deployBot = new DeployLevelOne();
        proxyAddress = deployBot.deployLevelOne();
        levelOneProxy = LevelOne(proxyAddress);

        // graduateBot = new GraduateToLevelTwo();

        usdc = deployBot.getUSDC();
        principal = deployBot.principal();
        schoolFees = deployBot.getSchoolFees();
        levelOneImplementationAddress = deployBot.getImplementationAddress();

        alice = makeAddr("first_teacher");
        bob = makeAddr("second_teacher");

        clara = makeAddr("first_student");
        dan = makeAddr("second_student");
        eli = makeAddr("third_student");
        fin = makeAddr("fourth_student");
        grey = makeAddr("fifth_student");
        harriet = makeAddr("six_student");

        usdc.mint(clara, schoolFees);
        usdc.mint(dan, schoolFees);
        usdc.mint(eli, schoolFees);
        usdc.mint(fin, schoolFees);
        usdc.mint(grey, schoolFees);
        usdc.mint(harriet, schoolFees);
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cma7694j20003l104u7xt4suj
    // `LevelOne::graduateAndUpgrade()` upgrades the proxy to `LevelTwo` and finalises the academic session but **never checks each student’s** `studentScore` **against** `cutOffScore`. Because `cutOffScore` is only set (in `LevelOne::startSession`) and never read/compared, the invariant _"Any student whose score is below the cut‑off must not be upgraded"_ is violated.
    function test_student_below_cutoff_still_graduates() public	schoolInSession {
        levelTwoImplementation = new LevelTwo();
        levelTwoImplementationAddress = address(levelTwoImplementation);

        bytes memory data = abi.encodeCall(LevelTwo.graduate, ());

        // Lower Harriet’s score from 100 → 60 (< cutOffScore)
        vm.startPrank(alice);
        for (uint256 i; i < 4; i++) {
            vm.warp(block.timestamp + 1 weeks);
            levelOneProxy.giveReview(harriet, false);
        }
        vm.stopPrank();

        assertLt(
            levelOneProxy.studentScore(harriet),
            levelOneProxy.cutOffScore()
        );

        vm.prank(principal);
        levelOneProxy.graduateAndUpgrade(levelTwoImplementationAddress, data);

        LevelTwo levelTwoProxy = LevelTwo(proxyAddress);

        // Harriet should not be a student anymore; assert should fail but passes
        assertTrue(levelTwoProxy.isStudent(harriet));
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cma5p51ge0005lb04tm5w4k3h
    // In calculating `payPerTeacher`, there is no division by the number of teachers, which means each teacher gets 35% of the bursary. This breaks a contract invariant and if there are 3 or more teachers, it will cause DOS of the upgrade functionality.
    function test_confirm_can_graduate() public schoolInSession {
        levelTwoImplementation = new LevelTwo();
        levelTwoImplementationAddress = address(levelTwoImplementation);

        bytes memory data = abi.encodeCall(LevelTwo.graduate, ());

        vm.prank(principal);
        levelOneProxy.graduateAndUpgrade(levelTwoImplementationAddress, data);

        LevelTwo levelTwoProxy = LevelTwo(proxyAddress);

        // console2.log(levelTwoProxy.bursary()); // this is a different bug.
        // expected = 60% = 2e22. actual = 25% = 7.5e21
        console2.log(usdc.balanceOf(address(levelTwoProxy))); //@audit
        console2.log(levelTwoProxy.getTotalStudents());
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cma6a8xk20005jv04b0s97im5
    // The graduateAndUpgrade function in the LevelOne contract misuses the UUPS pattern by calling _authorizeUpgrade without executing upgradeTo or upgradeToAndCall. This prevents the contract from upgrading to LevelTwo, leaving it on outdated logic and risking fund mismanagement or loss of functionality.
    function test_graduateAndUpgradeFailsToUpgrade() public schoolInSession {
        address proxyAddr = address(levelOneProxy);

        // Get current implementation via storage slot
        bytes32 slot = bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc));
        address initialImplementation = address(uint160(uint256(vm.load(proxyAddr, slot))));

        // Deploy LevelTwo
        LevelTwo levelTwo = new LevelTwo();
        address levelTwoAddress = address(levelTwo);

        // Call graduateAndUpgrade as principal
        vm.prank(principal);
        levelOneProxy.graduateAndUpgrade(levelTwoAddress, "");

        // Check implementation remains unchanged
        address finalImplementation = address(uint160(uint256(vm.load(proxyAddr, slot))));
        assertEq(
            finalImplementation, 
            initialImplementation,
            "Proxy implementation should remain unchanged (vulnerability confirmed)"
        );
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cma77y1sa0005jy04qps67sss
    function test_validate_bursary_after_upgrade() public schoolInSession {
        uint256  bursaryBefore = levelOneProxy.bursary();
        assertEq(bursaryBefore, usdc.balanceOf(address(levelOneProxy)));
    
        levelTwoImplementation = new LevelTwo();
        levelTwoImplementationAddress = address(levelTwoImplementation);
    
        bytes memory data = abi.encodeCall(LevelTwo.graduate, ());
    
        vm.prank(principal);
        levelOneProxy.graduateAndUpgrade(levelTwoImplementationAddress, data);
        LevelTwo levelTwoProxy = LevelTwo(proxyAddress);
    
        assertEq(levelTwoProxy.bursary(), usdc.balanceOf(address(levelTwoProxy)));
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cma8hc5ml0005kt04dmuhukma
    // The LevelTwo implementation does not maintain consistent storage layout with LevelOne, creating a dangerous mismatch between the contract's code and its storage. After upgrading, functions from LevelOne remain accessible through the proxy and operate on storage variables not declared in LevelTwo, risking silent data corruption.
    function test_UpgradeableImplementationVulnerability_WithImpact() public {
        // Setup minimal state with no students (to avoid token transfers)
        vm.startPrank(principal);
        levelOneProxy.addTeacher(alice);
        vm.stopPrank();

        console2.log("==================== BEFORE UPGRADE ====================");
        // 1. Set a custom value for schoolFees directly through LevelOne
        vm.prank(principal);
        // Use vm.store to directly set schoolFees to avoid any function calls
        bytes32 schoolFeesSlot = bytes32(uint256(1)); // schoolFees slot
        uint256 customFees = 12345;
        vm.store(address(levelOneProxy), schoolFeesSlot, bytes32(customFees));

        // Verify our direct storage write worked
        uint256 verifySchoolFees = levelOneProxy.getSchoolFeesCost();
        console2.log("Custom School Fees set in LevelOne:", verifySchoolFees);
        assertEq(verifySchoolFees, customFees, "Direct storage write failed");

        // 2. Now upgrade to LevelTwo WITHOUT calling graduateAndUpgrade
        //    (to avoid token transfers)
        levelTwoImplementation = new LevelTwo();

        // Directly set the implementation using the ERC1967 storage slot
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        vm.store(
            address(levelOneProxy),
            implSlot,
            bytes32(uint256(uint160(address(levelTwoImplementation))))
        );

        // Call LevelTwo's initialize function directly
        vm.prank(principal);
        (bool success, ) = address(levelOneProxy).call(
            abi.encodeWithSignature("graduate()")
        );

        console2.log("==================== AFTER UPGRADE ====================");
        console2.log("Upgrade successful:", success);

        // 3. Prove we are using LevelTwo by checking constants
        LevelTwo levelTwoProxy = LevelTwo(address(levelOneProxy));
        console2.log(
            "LevelTwo constant TEACHER_WAGE_L2:",
            levelTwoProxy.TEACHER_WAGE_L2()
        );
        assertTrue(
            levelTwoProxy.TEACHER_WAGE_L2() == 40,
            "Not using LevelTwo implementation"
        );

        // 4. KEY PROOF: Directly read the schoolFees storage slot
        // Even though LevelTwo doesn't declare this variable, the storage slot still exists!
        bytes32 storedFeesBytes = vm.load(
            address(levelOneProxy),
            schoolFeesSlot
        );
        uint256 storedFees = uint256(storedFeesBytes);
        console2.log(
            "Reading schoolFees storage slot after upgrade:",
            storedFees
        );
        assertEq(
            storedFees,
            customFees,
            "schoolFees was not preserved in storage"
        );

        // 5. Prove the vulnerability: we can modify this undeclared variable
        uint256 corruptedValue = 999;
        console2.log("Corrupting schoolFees storage slot with:", corruptedValue);
        vm.store(
            address(levelOneProxy),
            schoolFeesSlot,
            bytes32(corruptedValue)
        );

        // Verify corruption
        bytes32 corruptedBytes = vm.load(
            address(levelOneProxy),
            schoolFeesSlot
        );
        uint256 corruptedFees = uint256(corruptedBytes);
        console2.log("Value after corruption:", corruptedFees);
        assertEq(corruptedFees, corruptedValue, "Failed to corrupt storage");

        console2.log("==================== IMPACT ====================");
        console2.log("Original schoolFees:", customFees);
        console2.log("Corrupted schoolFees:", corruptedFees);
        console2.log(
            "This proves that a key state variable is still accessible in"
        );
        console2.log("storage but not declared in the LevelTwo implementation.");
        console2.log(
            "If LevelTwo uses this same storage slot for a different purpose,"
        );
        console2.log("it would corrupt the original schoolFees variable.");

        console2.log("==================== CONCLUSION ====================");
        console2.log("STORAGE LAYOUT VULNERABILITY CONFIRMED:");
        console2.log(
            "1. After upgrading to LevelTwo, the schoolFees storage slot still exists"
        );
        console2.log(
            "2. LevelTwo doesn't declare the schoolFees variable, creating a mismatch"
        );
        console2.log(
            "3. The variable can be corrupted if LevelTwo uses the same storage slot"
        );
      
    }

    // https://codehawks.cyfrin.io/c/2025-05-hawk-high/s/cmadqasau0009lh04od5a53vi
    function testReinitializeLogic() public {
        // Initialize the proxy with the first implementation
        deployBot = new DeployLevelOne();
        proxyAddress = deployBot.deployLevelOne();
    
        address attacker = makeAddr("attacker");
    
        LevelOne levelOneImplementation = new LevelOne();
        // Initialize directly, not via proxy
        LevelOne(address(levelOneImplementation)).initialize(attacker, schoolFees, address(usdc));
    
        assertEq(levelOneImplementation.getPrincipal(), attacker);
    }

    function test_confirm_first_deployment_is_level_one() public view {
        uint256 expectedTeacherWage = 35;
        uint256 expectedPrincipalWage = 5;
        uint256 expectedPrecision = 100;

        assertEq(levelOneProxy.TEACHER_WAGE(), expectedTeacherWage);
        assertEq(levelOneProxy.PRINCIPAL_WAGE(), expectedPrincipalWage);
        assertEq(levelOneProxy.PRECISION(), expectedPrecision);
        assertEq(levelOneProxy.getPrincipal(), principal);
        assertEq(levelOneProxy.getSchoolFeesCost(), deployBot.schoolFees());
        assertEq(levelOneProxy.getSchoolFeesToken(), address(usdc));
    }

    function test_confirm_add_teacher() public {
        vm.startPrank(principal);
        levelOneProxy.addTeacher(alice);
        levelOneProxy.addTeacher(bob);
        vm.stopPrank();

        assert(levelOneProxy.isTeacher(alice) == true);
        assert(levelOneProxy.isTeacher(bob) == true);
        assert(levelOneProxy.getTotalTeachers() == 2);
    }

    function test_confirm_cannot_add_teacher_if_not_principal() public {
        vm.expectRevert(LevelOne.HH__NotPrincipal.selector);
        levelOneProxy.addTeacher(alice);
    }

    function test_confirm_cannot_add_teacher_twice() public {
        vm.prank(principal);
        levelOneProxy.addTeacher(alice);

        vm.prank(principal);
        vm.expectRevert(LevelOne.HH__TeacherExists.selector);
        levelOneProxy.addTeacher(alice);
    }

    function test_confirm_remove_teacher() public {
        vm.startPrank(principal);
        levelOneProxy.addTeacher(alice);
        levelOneProxy.addTeacher(bob);
        vm.stopPrank();

        vm.prank(principal);
        levelOneProxy.removeTeacher(alice);

        assert(levelOneProxy.isTeacher(alice) == false);
        assert(levelOneProxy.getTotalTeachers() == 1);
    }

    function test_confirm_enroll() public {
        vm.startPrank(clara);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        assert(usdc.balanceOf(address(levelOneProxy)) == schoolFees);
    }

    function test_confirm_cannot_enroll_without_school_fees() public {
        address newStudent = makeAddr("no_school_fees");

        vm.prank(newStudent);
        vm.expectRevert();
        levelOneProxy.enroll();
    }

    function test_confirm_cannot_enroll_twice() public {
        vm.startPrank(eli);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.prank(eli);
        vm.expectRevert(LevelOne.HH__StudentExists.selector);
        levelOneProxy.enroll();
    }

    modifier schoolInSession() {
        _teachersAdded();
        _studentsEnrolled();

        vm.prank(principal);
        levelOneProxy.startSession(70);

        _;
    }

    function test_confirm_can_give_review() public schoolInSession {
        vm.warp(block.timestamp + 1 weeks);

        vm.prank(alice);
        levelOneProxy.giveReview(harriet, false);

        assert(levelOneProxy.studentScore(harriet) == 90);
    }

    // ////////////////////////////////
    // /////                      /////
    // /////   HELPER FUNCTIONS   /////
    // /////                      /////
    // ////////////////////////////////

    function _teachersAdded() internal {
        vm.startPrank(principal);
        levelOneProxy.addTeacher(alice);
        levelOneProxy.addTeacher(bob);
        vm.stopPrank();
    }

    function _studentsEnrolled() internal {
        vm.startPrank(clara);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.startPrank(dan);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.startPrank(eli);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.startPrank(fin);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.startPrank(grey);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();

        vm.startPrank(harriet);
        usdc.approve(address(levelOneProxy), schoolFees);
        levelOneProxy.enroll();
        vm.stopPrank();
    }
}
