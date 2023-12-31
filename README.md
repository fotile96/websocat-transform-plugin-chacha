## Example Usage

Make sure your websocat compiled with `--features=native_plugins`.

```
export WEBSOCAT_TRANSFORM_KEY="Your key here"

./websocat -Eb native_plugin_transform_b:tcp-l:127.0.0.1:1234 native_plugin_transform_a:mirror: --native-plugin-a dec@libfoo.so --native-plugin-b enc@libfoo.so

nc 127.0.0.1 1234
```

You may use https://github.com/fotile96/websocat/tree/transform-preserve-buffer which ensures that we always have empty room in the buffer to hold the iv.