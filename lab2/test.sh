#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

make

printf '%s\n' \
  '2400013518@stu.pku.edu.cn' \
  'key' \
  '2400013518@stu.pku.edu.cn' \
  '2328195213@qq.com' | ./send_email
