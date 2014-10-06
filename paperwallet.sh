#!/bin/bash

# paper wallet generator
#
# takes a list of addresses and privkeys (as produced by bulkwallet.sh) on 
# stdin, produces HTML output with QR codes
#
# depends on base64 and qrencode

cat <<EOF
<html>
<body>
<h1>Paper Wallet for 
EOF
whoami
cat <<EOF
</h1><h2>Generated 
EOF
date
cat <<EOF
</h2>
<table style="table-layout: fixed; word-wrap: break-word; width: 800px;">
EOF

sed "s/\(.*\) \(.*\)/echo -en \"<tr><td style=\\\\\"text-align: center; width: 150px;\\\\\"><img src=\\\\\"data:image\/png;base64,\"; qrencode -l L -o - \1 | base64 -w 0; echo \"\\\\\" \\\\><\/td><td style=\\\\\"width: 500px; font-family: monospace;\\\\\"><p style=\\\\\"text-align: left;\\\\\">\1<\/p><p style=\\\\\"text-align: right;\\\\\">\2<\/p><\/td><td style=\\\\\"text-align: center; width: 150px;\\\\\"><img src=\\\\\"data:image\/png;base64,\"; qrencode -l L -o - \2 | base64 -w 0; echo \"\\\\\" \\\\><\/td><\/tr>\"/" | bash

cat <<EOF
</table>
</body>
</html>
EOF
