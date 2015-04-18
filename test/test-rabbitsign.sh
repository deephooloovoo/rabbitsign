#! /bin/sh

if test $# = "0" ; then
    echo "usage: $0 keynum"
    exit 99
fi

echo "  Generating a random application..."

echo "    ./randapp $1 >test.hex"
$TEST_EXEC ./randapp $1 >test.hex || { echo "error generating app ($?)" ; cp test.hex failed.hex ; exit 1 ; }

echo "  Testing that the unsigned app fails validation..."

echo "    ../src/rabbitsign -c test.hex"
$TEST_EXEC ../src/rabbitsign -c test.hex 2>/dev/null && { echo "success validating unsigned app" ; cp test.hex failed.hex ; exit 3 ; }

echo "  Signing the app with rabbitsign..."

echo "    ../src/rabbitsign -r test.hex -o test.sig"
$TEST_EXEC ../src/rabbitsign -r test.hex -o test.sig || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 2 ; }

echo "  Testing the signature..."

echo "    ../src/rabbitsign -c test.sig"
$TEST_EXEC ../src/rabbitsign -c test.sig || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 3 ; }
