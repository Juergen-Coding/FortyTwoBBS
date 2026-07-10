/*****************************************************************************
 *
 * Purpose: Import a directory tree as one file group with multiple areas.
 *
 *****************************************************************************/

#include "../lib/mbselib.h"
#include "../lib/users.h"
#include "../lib/mbsedb.h"
#include "mbfimport.h"
#include "mbftree.h"


extern int do_quiet;


/*
 * Copy a string only when it fits completely into the destination field.
 */
static int set_field(char *destination, size_t size, const char *source,
		     const char *label)
{
    size_t length = strlen(source);

    if (length >= size) {
	WriteError("%s is too long: %s", label, source);

	if (!do_quiet)
	    printf("%s is too long: %s\n", label, source);

	return FALSE;
    }

    memcpy(destination, source, length + 1);
    return TRUE;
}


/*
 * Convert a group or area name into a safe lowercase path component.
 */
static int make_path_component(const char *source, char *destination,
			       size_t size)
{
    size_t i;
    size_t out = 0;
    unsigned char character;

    if (size == 0)
	return FALSE;

    for (i = 0; source[i] != '\0'; i++) {
	character = (unsigned char)source[i];

	if (out + 1 >= size)
	    return FALSE;

	if (isalnum(character) ||
	    character == '_' ||
	    character == '-')
	    destination[out++] = (char)tolower(character);
	else
	    destination[out++] = '_';
    }

    if (out == 0)
	return FALSE;

    destination[out] = '\0';
    return TRUE;
}


/*
 * Derive a group name from the source directory.
 *
 * DOS-packed becomes DOS. Other directory names are converted to uppercase
 * and characters unsuitable for the twelve-character group field become '_'.
 */
static int derive_group_name(const char *source_root, char *destination,
			     size_t size)
{
    const char *name;
    const char *slash;
    size_t length;
    size_t i;
    size_t out = 0;
    unsigned char character;

    slash = strrchr(source_root, '/');
    name = slash ? slash + 1 : source_root;

    if (*name == '\0')
	return FALSE;

    length = strlen(name);

    if ((length > 7) &&
	(strcasecmp(name + length - 7, "-packed") == 0))
	length -= 7;

    for (i = 0; i < length; i++) {
	character = (unsigned char)name[i];

	if (out + 1 >= size)
	    return FALSE;

	if (isalnum(character) ||
	    character == '_' ||
	    character == '-')
	    destination[out++] = (char)toupper(character);
	else
	    destination[out++] = '_';
    }

    if (out == 0)
	return FALSE;

    destination[out] = '\0';
    return TRUE;
}


/*
 * Load an existing file group or create a new one.
 */
static int load_or_create_group(const char *name, struct _fgroup *result)
{
    char		    filename[PATH_MAX];
    char		    component[65];
    FILE		    *file;
    long		    position;
    int			    records = 0;
    int			    changed = FALSE;
    int			    have_local = FALSE;
    struct _fgrouphdr	    header;
    struct _fgroup	    record;
    struct _fgroup	    local;

    if ((strlen(name) == 0) || (strlen(name) > 12)) {
	WriteError("File group name must contain 1 through 12 characters");

	if (!do_quiet)
	    printf("File group name must contain 1 through 12 characters\n");

	return FALSE;
    }

    snprintf(filename, sizeof(filename), "%s/etc/fgroups.data",
	     getenv("MBSE_ROOT"));

    file = fopen(filename, "r+");

    if (file == NULL) {
	WriteError("$Can't open %s", filename);

	if (!do_quiet)
	    printf("Can't open %s: %s\n", filename, strerror(errno));

	return FALSE;
    }

    if (fread(&header, sizeof(header), 1, file) != 1) {
	WriteError("$Can't read header from %s", filename);
	fclose(file);
	return FALSE;
    }

    if ((header.hdrsize != sizeof(header)) ||
	(header.recsize != sizeof(record))) {
	WriteError("Unsupported file group database format");

	if (!do_quiet)
	    printf("Unsupported file group database format\n");

	fclose(file);
	return FALSE;
    }

    if (fseek(file, header.hdrsize, SEEK_SET) != 0) {
	WriteError("$Can't seek in %s", filename);
	fclose(file);
	return FALSE;
    }

    memset(&local, 0, sizeof(local));

    while (fread(&record, header.recsize, 1, file) == 1) {
	records++;

	if (!strcasecmp(record.Name, "LOCAL")) {
	    local = record;
	    have_local = TRUE;
	}

	if (!strcasecmp(record.Name, name)) {
	    position = ftell(file) - header.recsize;

	    if (record.Deleted || !record.Active) {
		record.Deleted = FALSE;
		record.Active = TRUE;

		if ((fseek(file, position, SEEK_SET) != 0) ||
		    (fwrite(&record, sizeof(record), 1, file) != 1)) {
		    WriteError("$Can't reactivate file group %s", name);
		    fclose(file);
		    return FALSE;
		}

		header.lastupd = (int)time(NULL);
		changed = TRUE;
	    }

	    if (changed) {
		if ((fseek(file, 0, SEEK_SET) != 0) ||
		    (fwrite(&header, sizeof(header), 1, file) != 1)) {
		    WriteError("$Can't update header in %s", filename);
		    fclose(file);
		    return FALSE;
		}
	    }

	    *result = record;
	    fclose(file);
	    chmod(filename, 0640);
	    return TRUE;
	}
    }

    if (records >= CFG.tic_groups) {
	WriteError("Maximum number of file groups reached: %d",
		   CFG.tic_groups);

	if (!do_quiet) {
	    printf(
		"Maximum number of file groups reached: %d\n",
		CFG.tic_groups
	    );
	}

	fclose(file);
	return FALSE;
    }

    memset(&record, 0, sizeof(record));

    if (!set_field(record.Name, sizeof(record.Name), name,
		   "File group name")) {
	fclose(file);
	return FALSE;
    }

    snprintf(record.Comment, sizeof(record.Comment),
	     "Imported directory tree: %s", name);

    record.Active = TRUE;
    record.StartDate = (int)time(NULL);
    record.FileGate = TRUE;
    record.Replace = TRUE;
    record.DupCheck = TRUE;
    record.Secure = TRUE;
    record.VirScan = TRUE;
    record.Announce = TRUE;
    record.FileId = TRUE;
    record.LinkSec.level = 1;
    record.LinkSec.flags = 1;

    if (have_local) {
	record.DLSec = local.DLSec;
	record.UPSec = local.UPSec;
	record.LTSec = local.LTSec;
	record.LinkSec = local.LinkSec;
	record.Upload = local.Upload;

	if (strlen(local.AnnGroup) &&
	    !set_field(record.AnnGroup, sizeof(record.AnnGroup),
		       local.AnnGroup, "Announcement group")) {
	    fclose(file);
	    return FALSE;
	}

	if (strlen(local.Convert) &&
	    !set_field(record.Convert, sizeof(record.Convert),
		       local.Convert, "Archiver")) {
	    fclose(file);
	    return FALSE;
	}
    }

    if (!strlen(record.AnnGroup) &&
	!set_field(record.AnnGroup, sizeof(record.AnnGroup),
		   "LOCAL", "Announcement group")) {
	fclose(file);
	return FALSE;
    }

    if (!set_field(record.BbsGroup, sizeof(record.BbsGroup), name,
		   "BBS group")) {
	fclose(file);
	return FALSE;
    }

    if (!make_path_component(name, component, sizeof(component))) {
	WriteError("Can't create path component for group %s", name);
	fclose(file);
	return FALSE;
    }

    if (snprintf(record.BasePath, sizeof(record.BasePath), "%s/%s",
		 CFG.ftp_base, component) >=
	(int)sizeof(record.BasePath)) {
	WriteError("Base path for group %s is too long", name);

	if (!do_quiet)
	    printf("Base path for group %s is too long\n", name);

	fclose(file);
	return FALSE;
    }

    if ((fseek(file, 0, SEEK_END) != 0) ||
	(fwrite(&record, sizeof(record), 1, file) != 1)) {
	WriteError("$Can't append file group %s", name);
	fclose(file);
	return FALSE;
    }

    header.lastupd = (int)time(NULL);

    if ((fseek(file, 0, SEEK_SET) != 0) ||
	(fwrite(&header, sizeof(header), 1, file) != 1)) {
	WriteError("$Can't update header in %s", filename);
	fclose(file);
	return FALSE;
    }

    fclose(file);
    chmod(filename, 0640);

    *result = record;

    Syslog('+', "Created file group %s with base path %s",
	   record.Name, record.BasePath);

    if (!do_quiet)
	printf("Created file group: %s\n", record.Name);

    return TRUE;
}


/*
 * Load an existing area from the requested group or create it.
 */
static int load_or_create_area(const char *category,
			       const struct _fgroup *group,
			       int *area_number)
{
    char		    filename[PATH_MAX];
    char		    component[81];
    char		    create_path[PATH_MAX];
    char		    area_name[45];
    FILE		    *file;
    long		    position = -1;
    int			    number = 0;
    struct fileareashdr	    header;
    struct fileareas	    record;
    struct _fdbarea	    *file_database;

    if ((strlen(category) == 0) ||
	(snprintf(area_name, sizeof(area_name), "%s/%s",
		  group->Name, category) >= (int)sizeof(area_name))) {
	WriteError("File area name is too long: %s/%s",
		   group->Name, category);

	if (!do_quiet)
	    printf("File area name is too long: %s/%s\n",
		   group->Name, category);

	return FALSE;
    }

    snprintf(filename, sizeof(filename), "%s/etc/fareas.data",
	     getenv("MBSE_ROOT"));

    file = fopen(filename, "r+");

    if (file == NULL) {
	WriteError("$Can't open %s", filename);

	if (!do_quiet)
	    printf("Can't open %s: %s\n", filename, strerror(errno));

	return FALSE;
    }

    if (fread(&header, sizeof(header), 1, file) != 1) {
	WriteError("$Can't read header from %s", filename);
	fclose(file);
	return FALSE;
    }

    if ((header.hdrsize != sizeof(header)) ||
	(header.recsize != sizeof(record))) {
	WriteError("Unsupported file area database format");

	if (!do_quiet)
	    printf("Unsupported file area database format\n");

	fclose(file);
	return FALSE;
    }

    if (fseek(file, header.hdrsize, SEEK_SET) != 0) {
	WriteError("$Can't seek in %s", filename);
	fclose(file);
	return FALSE;
    }

    while (fread(&record, header.recsize, 1, file) == 1) {
	number++;

	if (record.Available &&
	    !strcasecmp(record.BbsGroup, group->Name) &&
	    (!strcasecmp(record.Name, area_name) ||
	     !strcasecmp(record.Name, category))) {
	    if (strcasecmp(record.Name, area_name)) {
		long record_position = ftell(file) - header.recsize;

		if (!set_field(record.Name, sizeof(record.Name),
			       area_name, "File area name") ||
		    fseek(file, record_position, SEEK_SET) != 0 ||
		    fwrite(&record, sizeof(record), 1, file) != 1) {
		    WriteError("$Can't rename file area %s to %s",
			       category, area_name);
		    fclose(file);
		    return FALSE;
		}

		fflush(file);

		if (!do_quiet)
		    printf("Renamed file area %d: %s\n",
			   number, area_name);
	    }

	    fclose(file);
	    *area_number = number;
	    return TRUE;
	}
    }

    number = 0;

    if (fseek(file, header.hdrsize, SEEK_SET) != 0) {
	WriteError("$Can't seek in %s", filename);
	fclose(file);
	return FALSE;
    }

    while (fread(&record, header.recsize, 1, file) == 1) {
	number++;

	if (!record.Available) {
	    position = ftell(file) - header.recsize;
	    break;
	}
    }

    if (position == -1) {
	if (fseek(file, 0, SEEK_END) != 0) {
	    WriteError("$Can't seek to end of %s", filename);
	    fclose(file);
	    return FALSE;
	}

	position = ftell(file);
	number++;
    }

    memset(&record, 0, sizeof(record));

    if (!set_field(record.Name, sizeof(record.Name), area_name,
		   "File area name")) {
	fclose(file);
	return FALSE;
    }

    if (!make_path_component(category, component, sizeof(component))) {
	WriteError("Can't create path component for area %s", category);
	fclose(file);
	return FALSE;
    }

    if (snprintf(record.Path, sizeof(record.Path), "%s/%s",
		 group->BasePath, component) >=
	(int)sizeof(record.Path)) {
	WriteError("Path for file area %s is too long", category);

	if (!do_quiet)
	    printf("Path for file area %s is too long\n", category);

	fclose(file);
	return FALSE;
    }

    record.DLSec = group->DLSec;
    record.UPSec = group->UPSec;
    record.LTSec = group->LTSec;
    record.New = TRUE;
    record.Dupes = TRUE;
    record.Free = TRUE;
    record.FileFind = TRUE;
    record.AddAlpha = TRUE;
    record.Available = TRUE;
    record.FileReq = TRUE;
    record.Upload = group->Upload;

    if (!set_field(record.BbsGroup, sizeof(record.BbsGroup),
		   group->Name, "BBS group")) {
	fclose(file);
	return FALSE;
    }

    if (strlen(group->AnnGroup)) {
	if (!set_field(record.NewGroup, sizeof(record.NewGroup),
		       group->AnnGroup, "Newfiles group")) {
	    fclose(file);
	    return FALSE;
	}
    } else if (!set_field(record.NewGroup, sizeof(record.NewGroup),
			  "LOCAL", "Newfiles group")) {
	fclose(file);
	return FALSE;
    }

    if (strlen(group->Convert) &&
	!set_field(record.Archiver, sizeof(record.Archiver),
		   group->Convert, "Archiver")) {
	fclose(file);
	return FALSE;
    }

    if ((fseek(file, position, SEEK_SET) != 0) ||
	(fwrite(&record, sizeof(record), 1, file) != 1)) {
	WriteError("$Can't write file area %s", category);
	fclose(file);
	return FALSE;
    }

    fclose(file);
    chmod(filename, 0640);

    snprintf(create_path, sizeof(create_path),
	     "%s/foobar", record.Path);

    if (!mkdirs(create_path, 0775)) {
	WriteError("Can't create directory %s", record.Path);

	if (!do_quiet)
	    printf("Can't create directory %s\n", record.Path);

	return FALSE;
    }

    file_database = mbsedb_OpenFDB(number, 30);

    if (file_database == NULL) {
	WriteError("Can't create file database for area %d", number);

	if (!do_quiet)
	    printf("Can't create file database for area %d\n", number);

	return FALSE;
    }

    mbsedb_CloseFDB(file_database);

    Syslog('+', "Created file area %d %s in group %s",
	   number, area_name, group->Name);

    if (!do_quiet)
	printf("Created file area %d: %s\n", number, area_name);

    *area_number = number;
    return TRUE;
}


/*
 * Import each direct child directory as one area.
 */
int TreeImport(const char *source_root, const char *requested_group)
{
    char		    root[PATH_MAX];
    char		    original_directory[PATH_MAX];
    char		    category_path[PATH_MAX];
    char		    files_bbs[PATH_MAX];
    char		    group_name[13];
    struct dirent	    **entries = NULL;
    struct stat		    status;
    struct _fgroup	    group;
    int			    count;
    int			    index;
    int			    area_number;
    int			    imported_areas = 0;

    if (realpath(source_root, root) == NULL) {
	WriteError("$Can't resolve import directory %s", source_root);

	if (!do_quiet) {
	    printf("Can't resolve import directory %s: %s\n",
		   source_root, strerror(errno));
	}

	return FALSE;
    }

    if ((stat(root, &status) != 0) ||
	!S_ISDIR(status.st_mode)) {
	WriteError("Tree import source is not a directory: %s", root);

	if (!do_quiet)
	    printf("Tree import source is not a directory: %s\n", root);

	return FALSE;
    }

    if ((requested_group != NULL) && strlen(requested_group)) {
	if (!set_field(group_name, sizeof(group_name),
		       requested_group, "File group name"))
	    return FALSE;
    } else if (!derive_group_name(root, group_name,
				  sizeof(group_name))) {
	WriteError("Can't derive file group name from %s", root);

	if (!do_quiet)
	    printf("Can't derive file group name from %s\n", root);

	return FALSE;
    }

    if (getcwd(original_directory,
	       sizeof(original_directory)) == NULL) {
	WriteError("$Can't determine current directory");
	return FALSE;
    }

    if (!load_or_create_group(group_name, &group))
	return FALSE;

    count = scandir(root, &entries, NULL, alphasort);

    if (count < 0) {
	WriteError("$Can't scan directory %s", root);

	if (!do_quiet)
	    printf("Can't scan directory %s: %s\n",
		   root, strerror(errno));

	return FALSE;
    }

    for (index = 0; index < count; index++) {
	if (!strcmp(entries[index]->d_name, ".") ||
	    !strcmp(entries[index]->d_name, "..")) {
	    free(entries[index]);
	    continue;
	}

	if (snprintf(category_path, sizeof(category_path), "%s/%s",
		     root, entries[index]->d_name) >=
	    (int)sizeof(category_path)) {
	    WriteError("Category path is too long: %s",
		       entries[index]->d_name);
	    free(entries[index]);
	    continue;
	}

	if ((lstat(category_path, &status) != 0) ||
	    !S_ISDIR(status.st_mode)) {
	    free(entries[index]);
	    continue;
	}

	if ((snprintf(files_bbs, sizeof(files_bbs),
		      "%s/FILES.BBS", category_path) >=
	     (int)sizeof(files_bbs)) ||
	    (access(files_bbs, R_OK) != 0)) {
	    WriteError("Skipping %s: FILES.BBS is missing",
		       category_path);

	    if (!do_quiet) {
		printf("Skipping %s: FILES.BBS is missing\n",
		       entries[index]->d_name);
	    }

	    free(entries[index]);
	    continue;
	}

	if (!load_or_create_area(entries[index]->d_name,
				 &group, &area_number)) {
	    free(entries[index]);

	    while (++index < count)
		free(entries[index]);

	    free(entries);
	    return FALSE;
	}

	if (!do_quiet) {
	    printf("\nImporting %s into area %d\n",
		   entries[index]->d_name, area_number);
	}

	if (chdir(category_path) != 0) {
	    WriteError("$Can't change to directory %s",
		       category_path);

	    free(entries[index]);

	    while (++index < count)
		free(entries[index]);

	    free(entries);
	    return FALSE;
	}

	ImportFiles(area_number);

	if (chdir(original_directory) != 0) {
	    WriteError("$Can't restore working directory %s",
		       original_directory);

	    free(entries[index]);

	    while (++index < count)
		free(entries[index]);

	    free(entries);
	    return FALSE;
	}

	imported_areas++;
	free(entries[index]);
    }

    free(entries);

    if (imported_areas == 0) {
	WriteError("No importable category directories found in %s",
		   root);

	if (!do_quiet) {
	    printf("No importable category directories found in %s\n",
		   root);
	}

	return FALSE;
    }

    Syslog('+', "Tree import completed: group %s, %d areas",
	   group.Name, imported_areas);

    if (!do_quiet) {
	printf("\nTree import completed: group %s, %d areas\n",
	       group.Name, imported_areas);
    }

    return TRUE;
}
