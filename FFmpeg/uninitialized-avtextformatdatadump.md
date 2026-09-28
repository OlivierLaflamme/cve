# Uninitialized AVTextFormatDataDump causes undefined behavior in avtext_print_data()

**Reporter**: Olivier Laflamme  
**Pwno ID**: [`PWNO-0036`](https://pwno.io/0036)  
**Pwno index date**: 2026-03-12  
**Pwno status**: Patched  
**Component**: `fftools/ffprobe.c`, `fftools/textformat/avtextformat.c`

## Summary

FFmpeg's `ffprobe` declared `data_dump_format_id` as an uninitialized automatic
variable. The variable was assigned only when the optional `-data_dump_format`
argument was present, but it was always copied into `AVTextFormatOptions`.

When `-show_data` caused `avtext_print_data()` to format packet or side-data,
the function switched on that indeterminate enum. Values other than the two valid
enumerators reached `av_unreachable("Invalid data dump type")`, producing undefined
behavior instead of using the documented default `xxd` representation.

## Vulnerable code

Before the fix, `ffprobe.c` contained:

```c
int main(int argc, char **argv)
{
    // ...
    AVTextFormatDataDump data_dump_format_id;

    // Assigned only when the optional argument is present.
    if (data_dump_format) {
        if (!strcmp(data_dump_format, "xxd"))
            data_dump_format_id = AV_TEXTFORMAT_DATADUMP_XXD;
        else if (!strcmp(data_dump_format, "base64"))
            data_dump_format_id = AV_TEXTFORMAT_DATADUMP_BASE64;
        else
            goto end;
    }

    AVTextFormatOptions tf_options = {
        // ...
        .data_dump_format = data_dump_format_id,
    };
```

The value later controlled the formatter in `avtext_print_data()`:

```c
switch (tctx->opts.data_dump_format) {
case AV_TEXTFORMAT_DATADUMP_XXD:
    print_data_xxd(&bp, data, size);
    break;
case AV_TEXTFORMAT_DATADUMP_BASE64:
    print_data_base64(&bp, data, size);
    break;
default:
    av_unreachable("Invalid data dump type");
}
```

The affected path is reachable with normal `ffprobe -show_data` use when the user
does not also specify `-data_dump_format`.

## Fix

FFmpeg initialized the local enum to the intended default:

```diff
-    AVTextFormatDataDump data_dump_format_id;
+    AVTextFormatDataDump data_dump_format_id = AV_TEXTFORMAT_DATADUMP_XXD;
```

The upstream fix is commit
[`10d36e5d3d1b930ee9efc3840a8c72832f5ca404`](https://github.com/FFmpeg/FFmpeg/commit/10d36e5d3d1b930ee9efc3840a8c72832f5ca404),
authored by Olivier Laflamme on **2026-03-12** and committed by Michael Niedermayer
on **2026-03-13**.

The same change was backported to FFmpeg's `release/8.1` branch as
[`711b69c6158d27da878e29d681b4f0680374b645`](https://github.com/FFmpeg/FFmpeg/commit/711b69c6158d27da878e29d681b4f0680374b645)
on **2026-03-14**.

## References

- [Pwno vulnerability index](https://pwno.io/diff)
- [Upstream fix](https://github.com/FFmpeg/FFmpeg/commit/10d36e5d3d1b930ee9efc3840a8c72832f5ca404)
- [FFmpeg release/8.1 backport](https://github.com/FFmpeg/FFmpeg/commit/711b69c6158d27da878e29d681b4f0680374b645)

