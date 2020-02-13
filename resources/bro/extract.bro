# html is possibly too verbose for auto extraction
#     ["text/html"] = "html",

global ext_map: table[string] of string = {
    ["application/x-shockwave-flash"] = "swf",
    ["application/zip"] = "zip",
    ["application/pdf"] = "pdf",
    ["application/x-dosexec"] = "exe",
    ["application/x-bzip2"] = "bz2",
    ["application/java-archive"] = "jar",
    ["application/x-7z-compressed"] = "7z",
    ["application/msword"] = "doc",
    ["application/x-lz4"] = "lz",
    ["application/x-rar"] = "rar",
    ["application/x-xz"] = "xz",
    ["application/x-xar"] = "xar",
    ["application/x-dmg"] = "dmg",
    ["application/x-lzma"] = "lzma",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
    ["text/rtf"] = "rtf",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
    ["application/vnd.openxmlformats-officedocument"] = "doc",
    ["application/x-java-applet"] = "applet",
} &default ="";

#event file_new(f: fa_file)
#    {
#
#    if ( ! f?$mime_type || ext_map[f$mime_type] == "" )
#        return;
#
#    local ext = "";
#
#    if ( f?$mime_type )
#        ext = ext_map[f$mime_type];
#
#    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
#    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
#    }


event file_sniff(f: fa_file, meta: fa_metadata)
    {

    if ( ! meta?$mime_type || ext_map[meta$mime_type] == "" )
        return;

    local ext = "";

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }

