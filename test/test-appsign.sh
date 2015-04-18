#! /bin/sh

echo "  Generating a random application..."

echo "    ./randapp 0104 >test.hex"
          ./randapp 0104 >test.hex || { echo "error generating app ($?)" ; exit 1 ; }

echo "  Signing the app with appsign..."

echo "    appsign test"
          appsign test >/dev/null || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 4 ; }
echo "    mv test.app testas.app"
          mv test.app testas.app || { echo "error renaming app ($?)" ; exit 1 ; }

echo "  Testing the signature..."

echo "    ../src/rabbitsign -c testas.app -k 0104.key"
          ../src/rabbitsign -c testas.app -k 0104.key || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 5 ; }

echo "  Signing the app (all four ways) with rabbitsign and testing"
echo "  each signature..."

echo "    ../src/rabbitsign -a -R0 -o testr0.app test.hex -k 0104.key"
          ../src/rabbitsign -a -R0 -o testr0.app test.hex -k 0104.key || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 2 ; }
echo "    ../src/rabbitsign -c testr0.app -k 0104.key"
          ../src/rabbitsign -c testr0.app -k 0104.key || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 3 ; }

echo "    ../src/rabbitsign -a -R1 -o testr1.app test.hex -k 0104.key"
          ../src/rabbitsign -a -R1 -o testr1.app test.hex -k 0104.key || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 2 ; }
echo "    ../src/rabbitsign -c testr1.app -k 0104.key"
          ../src/rabbitsign -c testr1.app -k 0104.key || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 3 ; }

echo "    ../src/rabbitsign -a -R2 -o testr2.app test.hex -k 0104.key"
          ../src/rabbitsign -a -R2 -o testr2.app test.hex -k 0104.key || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 2 ; }
echo "    ../src/rabbitsign -c testr2.app -k 0104.key"
          ../src/rabbitsign -c testr2.app -k 0104.key || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 3 ; }

echo "    ../src/rabbitsign -a -R3 -o testr3.app test.hex -k 0104.key"
          ../src/rabbitsign -a -R3 -o testr3.app test.hex -k 0104.key || { echo "error signing app ($?)" ; cp test.hex failed.hex ; exit 2 ; }
echo "    ../src/rabbitsign -c testr3.app -k 0104.key"
          ../src/rabbitsign -c testr3.app -k 0104.key || { echo "error validating app ($?)" ; cp test.hex failed.hex ; exit 3 ; }

echo "  Testing that exactly one of the signatures matches the"
echo "  appsign signature..."

echo "    diff testr0.app testas.app"
          diff testr0.app testas.app >/dev/null ; STAT0=$?

echo "    diff testr1.app testas.app"
          diff testr1.app testas.app >/dev/null ; STAT1=$?

echo "    diff testr2.app testas.app"
          diff testr2.app testas.app >/dev/null ; STAT2=$?

echo "    diff testr3.app testas.app"
          diff testr3.app testas.app >/dev/null ; STAT3=$?

if test $STAT0 = 0 -a $STAT1 != 0 -a $STAT2 != 0 -a $STAT3 != 0 ; then
    echo "  OK, root 0 matches"
elif test $STAT0 != 0 -a $STAT1 = 0 -a $STAT2 != 0 -a $STAT3 != 0 ; then
    echo "  OK, root 1 matches"
elif test $STAT0 != 0 -a $STAT1 != 0 -a $STAT2 = 0 -a $STAT3 != 0 ; then
    echo "  OK, root 2 matches"
elif test $STAT0 != 0 -a $STAT1 != 0 -a $STAT2 != 0 -a $STAT3 = 0 ; then
    echo "  OK, root 3 matches"
elif test $STAT0 != 0 -a $STAT1 != 0 -a $STAT2 != 0 -a $STAT3 != 0 ; then
    echo "  No signature matches!"
    cp test.hex failed.hex
    diff testas.app testr0.app
    exit 6
else
    echo "  Multiple signatures match!"
    cp test.hex failed.hex
    exit 7
fi
