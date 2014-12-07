# html is possibly too verbose for auto extraction
#     ["text/html"] = "html",

global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["application/x-java-applet"] = "class",
    ["application/x-java-archive"] = "jar",
    ["application/zip"] = "zip",
    ["application/pdf"] = "pdf",
    ["application/x-rar"] = "rar",
} &default ="";

event file_new(f: fa_file)
    {

    if ( ! f?$mime_type || ext_map[f$mime_type] == "" )
        return;

    local ext = "";

    if ( f?$mime_type )
        ext = ext_map[f$mime_type];

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
