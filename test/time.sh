#!/bin/sh

[ -f 0104.key ] || ../src/rskeygen --ti > 0104.key

echo "Testing: $1 iterations of randapp"

time sh<<EOF
    for ((i=0; i<$1; i++)) do
        ./randapp 0104 >test.hex
    done
EOF

echo "Testing: $1 iterations of rabbitsign"

time sh<<EOF
    for ((i=0; i<$1; i++)) do
	./randapp 0104 >test.hex
	../src/rabbitsign test.hex -vv >&/dev/null
    done
EOF

echo "Testing: $1 iterations of appsign"

time sh<<EOF
    for ((i=0; i<$1; i++)) do
	./randapp 0104 >test.hex
	./appsign -a test >&/dev/null
    done
EOF

