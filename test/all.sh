# test everything
coffee -c test/*-spec.coffee
node test/helpers-spec
echo
node test/address-spec
echo
node test/invite-spec
echo
node test/link-codecs-spec
echo
node test/link-spec
echo
rm test/*-spec.js
