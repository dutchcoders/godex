# godex
Android DEX file analyzer library. With this go library you can extract metadata from DEX (Dalvik) java class files. 

## Usage
```
dex, err := Open("classes.dex")

if err != nil {
    t.Errorf("%s", err)
}

dex.Dump()
```

## References
- https://source.android.com/devices/tech/dalvik/dex-format.html
- https://android.googlesource.com/platform/dalvik2/+/master

## Contributions

Contributions are welcome.

## Creators

**Remco Verhoef**
- <https://twitter.com/remco_verhoef>
- <https://twitter.com/dutchcoders>

## Copyright and license

Code and documentation copyright 2011-2014 Remco Verhoef.

Code released under [the MIT license](LICENSE).

