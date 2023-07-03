#!/bin/bash

cd "$(dirname $0)"/../..

set -e

./utils/format.sh

git --no-pager diff --exit-code --color || (echo -ne '\n\n\e[31;1m⚠☝ Lint check failed! ☣ Please run ./utils/format.sh\e[0m\n\n' ; exit 1)

echo -ne '\n\e[32;1m🎉 Lint check passed! 🎊\e[0m\n\n'
