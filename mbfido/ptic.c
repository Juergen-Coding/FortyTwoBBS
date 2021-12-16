/*****************************************************************************
 *
 * Purpose ...............: Process 1 .tic file
 *
 *****************************************************************************
 * Copyright (C) 1997-2011
 *   
 * Michiel Broek		FIDO:		2:280/2802
 * Beekmansbos 10
 * 1971 BV IJmuiden
 * the Netherlands
 *
 * This file is part of MBSE BBS.
 *
 * This BBS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * MBSE BBS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MBSE BBS; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *****************************************************************************/

#include "../lib/mbselib.h"
#include "../lib/users.h"
#include "../lib/mbsedb.h"
#include "unpack.h"
#include "mover.h"
#include "toberep.h"
#include "orphans.h"
#include "tic.h"
#include "utic.h"
#include "magic.h"
#include "forward.h"
#include "rollover.h"
#include "ptic.h"
#include "magic.h"
#include "createf.h"
#include "qualify.h"
#include "addbbs.h"



#define	UNPACK_FACTOR	300

extern	int	tic_bad;
extern	int	tic_dup;
extern	int	tic_out;
extern	int	do_quiet;
extern	int	check_crc;
extern	int	check_dupe;


/*
 * Return values:
 * 0 - Success
 * 1 - Some error
 * 2 - Orphaned tic
 */
int ProcessTic(fa_list **sbl, orphans **opl)
{
    int		    First, Listed = FALSE, DownLinks = 0, MustRearc = FALSE;
    int		    UnPacked = FALSE, IsArchive = FALSE, rc, i, j, k;
    char	    *unarc = NULL, *cmd = NULL;
    char	    sbe[24], TDesc[1024];
    unsigned int    crc, crc2, Kb;
    sysconnect	    Link;
    FILE	    *fp;
    struct utimbuf  ut;
    int		    BBS_Imp = FALSE, DidBanner = FALSE;
    faddr	    *p_from;
    qualify	    *qal = NULL, *tmpq;
    orphans	    *topl;

    if (TIC.TicIn.PathError) {
	WriteError("Our Aka is in the path");
	tic_bad++;
	return 1;
    }

    if (!do_quiet) {
	mbse_colour(LIGHTGREEN, BLACK);
	printf("Checking  \b\b\b\b\b\b\b\b\b\b");
	fflush(stdout);
    }

    if (TIC.Orphaned) {
	fill_orphans(opl, TIC.TicName, TIC.TicIn.Area, TIC.TicIn.File, TRUE, FALSE);
	Syslog('+', "File not in inbound: %s", TIC.TicIn.File);
	return 2;
    }

    char *path_tic = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
	if (NULL == path_tic) {
		WriteError("Unable to join paths %s and %s", TIC.Inbound, TIC.TicIn.File);
		free(path_tic);
		return 2;
	}
    crc = file_crc(path_tic, CFG.slow_util && do_quiet);
    TIC.FileSize = file_size(path_tic);
    TIC.FileDate = file_time(path_tic);

    if (TIC.TicIn.Size) {
	if (TIC.TicIn.Size != TIC.FileSize)
	    WriteError("Size is %ld, expected %ld", TIC.FileSize, TIC.TicIn.Size);
    } else {
	/*
	 * No filesize in TIC file, add filesize.
	 */
	TIC.TicIn.Size = TIC.FileSize;
    }

    if (TIC.Crc_Int) {
	if (crc != TIC.Crc_Int) {
	    Syslog('!', "CRC: expected %08lX, the file is %08lX", TIC.Crc_Int, crc);
	    fill_orphans(opl, TIC.TicName, TIC.TicIn.Area, TIC.TicIn.File, FALSE, TRUE);
	    if (check_crc) {
		Syslog('+', "Bad CRC, will check this ticfile later");
		free(path_tic);
		return 1;
	    } else {
		Syslog('!', "CRC: error, recalculating crc");
		ReCalcCrc(path_tic);
	    }
	}
    } else {
	Syslog('+', "CRC: missing, calculating CRC");
	ReCalcCrc(path_tic);
    }

    /*
     * Load and check the .TIC area.
     */
    if (!SearchTic(TIC.TicIn.Area)) {
	UpdateNode();
	Syslog('f', "Unknown file area %s", TIC.TicIn.Area);
	p_from = fido2faddr(TIC.Aka);
	if (!create_ticarea(TIC.TicIn.Area, p_from)) {
	    Bad((char *)"Unknown file area %s", TIC.TicIn.Area);
	    free(path_tic);
	    tidy_faddr(p_from);
	    return 1;
	}
	tidy_faddr(p_from);
	/*
	 * Try to load the .TIC area again.
	 */
	if (!SearchTic(TIC.TicIn.Area)) {
	    Bad((char *)"Reload of new created file area %s failed", TIC.TicIn.Area);
	    free(path_tic);
	    return 1;
	}
    }

    if ((tic.Secure) && (!TIC.TicIn.Hatch)) {
	First = TRUE;
	while (GetTicSystem(&Link, First)) {
	    First = FALSE;
	    if (Link.aka.zone) {
		if ((Link.aka.zone == TIC.Aka.zone) && (Link.aka.net  == TIC.Aka.net) &&
		    (Link.aka.node == TIC.Aka.node) && (Link.aka.point== TIC.Aka.point) && (Link.receivefrom)) 
		    Listed = TRUE;
	    }
	}
	if (!Listed) {
	    Bad((char *)"%s NOT connected to %s", aka2str(TIC.Aka), TIC.TicIn.Area);
	    free(path_tic);
	    return 1;
	}
    }

    if ((!SearchNode(TIC.Aka)) && (!TIC.TicIn.Hatch)) {
	Bad((char *)"%s NOT known", aka2str(TIC.Aka));
	free(path_tic);
	return 1;
    }

    if (!TIC.TicIn.Hatch) {
	if (strcasecmp(TIC.TicIn.Pw, nodes.Fpasswd)) {
	    Bad((char *)"Pwd error, got %s, expected %s", TIC.TicIn.Pw, nodes.Fpasswd);
	    free(path_tic);
	    return 1;
	}
    } else {
	if (strcasecmp(TIC.TicIn.Pw, CFG.hatchpasswd)) {
	    Bad((char *)"Password error in local Hatch");
	    WriteError("WARNING: it might be a Trojan in your inbound");
	    free(path_tic);
	    return 1;
	}
    }

    if (Magic_DeleteFile()) {
		char *path_tmp = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicName, sizeof(TIC.TicName));
		if (NULL == path_tmp) {
			WriteError("Unable to join paths for file deletion: %s/%s", TIC.Inbound, TIC.TicName);
			file_rm(path_tic);
			free(path_tic);
			return 0;
		} else {
			file_rm(path_tmp);
			Syslog('+', "Deleted file %s", path_tmp);
			file_rm(path_tic);
			free(path_tic);
			free(path_tmp);
			return 0;
		}
    }


    if (Magic_MoveFile()) {
	if (!SearchTic(TIC.TicIn.Area)) {
	    Bad((char *)"Unknown Area: %s", TIC.TicIn.Area);
	    free(path_tic);
	    return 1;
	}
    }

    memcpy(T_File.Echo, tic.Name, 20);
    memcpy(T_File.Group, tic.Group, 12);
    TIC.KeepNum = tic.KeepLatest;

    Magic_Keepnum();

    if (!tic.FileArea) {
	Syslog('+', "Passthru TIC area!");
	strcpy(TIC.BBSpath, CFG.ticout);
	strcpy(TIC.BBSdesc, tic.Comment);
    } else {
		free(path_tic);
		char *root = getenv("MBSE_ROOT");
		size_t root_len = strlen(root);
		const char fareas_data[] = "/etc/fareas.data";
		char *path_tmp = join_paths(root, root_len, fareas_data, sizeof(fareas_data));
		if (NULL == path_tmp) {
			WriteError("Could not join paths %s and %s", root, fareas_data);
			return 1;
		}
	if ((fp = fopen(path_tmp, "r")) == NULL) {
	    WriteError("Can't access fareas.data area: %ld", tic.FileArea);
	    free(path_tmp);
	    return 1;
	}
	fread(&areahdr, sizeof(areahdr), 1, fp);
	if (fseek(fp, ((tic.FileArea -1) * areahdr.recsize) + areahdr.hdrsize, SEEK_SET)) {
	    fclose(fp);
	    WriteError("Can't seek area %ld in fareas.data", tic.FileArea);
	    free(path_tmp);
	    return 1;
	}
	if (fread(&area, areahdr.recsize, 1, fp) != 1) {
	    fclose(fp);
	    WriteError("Can't read area %ld in fareas.data", tic.FileArea);
	    free(path_tmp);
	    return 1;
	}
	free(path_tmp);
	fclose(fp);
	strcpy(TIC.BBSpath, area.Path);
	strcpy(TIC.BBSdesc, area.Name);

	/*
	 * If the File area has a special announce group, change
	 * the group to that name.
	 */
	if (strlen(area.NewGroup))
	    memcpy(T_File.Group, area.NewGroup, 12);
    }
    memcpy(T_File.Comment, tic.Comment, 55);

    /*
     * Check if the destination area really exists, it may be that
     * the area is not linked to an existing BBS area.
     */
    if (tic.FileArea && access(TIC.BBSpath, W_OK)) {
	WriteError("No write access to \"%s\"", TIC.BBSpath);
	Bad((char *)"Dest directory not available");
	return 1;
    }

    if ((tic.DupCheck) && (check_dupe)) {
		char *path_tmp = join_paths(TIC.TicIn.Area, sizeof(TIC.TicIn.Area), TIC.TicIn.Crc, sizeof(TIC.TicIn.Crc));
		if (NULL == path_tmp) {
			WriteError("Unable to join paths on %s and %s", TIC.TicIn.Area, TIC.TicIn.Crc);
			return 1;
		}
		crc2 = 0xffffffff;
		crc2 = upd_crc32(path_tmp, crc2, strlen(path_tmp));
		if (CheckDupe(crc2, D_FILEECHO, CFG.tic_dupes)) {
			Bad((char *)"Duplicate file");
			tic_dup++;
			free(path_tmp);
			return 1;
		}
    }

    /*
     * Count the actual downlinks for this area and build the list of
     * systems qualified to receive this file.
     */
    First = TRUE;
    while (GetTicSystem(&Link, First)) {
	First = FALSE;
	if ((Link.aka.zone) && (Link.sendto) && (!Link.pause)) {
	    DownLinks++;
	    p_from = fido2faddr(Link.aka);
	    if (TIC.TicIn.Hatch) {
		fill_qualify(&qal, Link.aka, FALSE, in_list(p_from, sbl, TRUE));
	    } else {
		fill_qualify(&qal, Link.aka, ((TIC.Aka.zone == Link.aka.zone) &&
			(TIC.Aka.net == Link.aka.net) && (TIC.Aka.node == Link.aka.node) &&
			(TIC.Aka.point == Link.aka.point)), in_list(p_from, sbl, TRUE));
	    }
	    tidy_faddr(p_from);
	}
    }

    T_File.Size = TIC.FileSize;
    T_File.SizeKb = TIC.FileSize / 1024;

    /*
     * Update the uplink's counters.
     */
    Kb = TIC.FileSize / 1024;
    if (SearchNode(TIC.Aka)) {
	StatAdd(&nodes.FilesRcvd, 1L);
	StatAdd(&nodes.F_KbRcvd, Kb);
	UpdateNode();
	SearchNode(TIC.Aka);
    }

    /*
     * Update the fileecho and group counters.
     */
    StatAdd(&fgroup.Files, 1L);
    StatAdd(&fgroup.KBytes, Kb);
    fgroup.LastDate = time(NULL);
    StatAdd(&tic.Files, 1L);
    StatAdd(&tic.KBytes, Kb);
    tic.LastAction = time(NULL);
    UpdateTic();

    if (!do_quiet) {
	printf("Unpacking \b\b\b\b\b\b\b\b\b\b");
	fflush(stdout);
    }

    /*
     * Check if this is an archive, and if so, which compression method
     * is used for this file.
     */
    if (strlen(tic.Convert) || tic.FileId || tic.ConvertAll || strlen(tic.Banner)) {
	/*
	 * Create tmp workdir
	 */
	if (create_tmpwork()) {
	    tidy_qualify(&qal);
	    return 1;
	}

	if ((unarc = unpacker(TIC.TicIn.File)) == NULL)
	    Syslog('+', "Unknown archive format %s", TIC.TicIn.File);
	else {
	    IsArchive = TRUE;
	    if ((strlen(tic.Convert) && (strcmp(unarc, tic.Convert) == 0)) || (tic.ConvertAll))
		MustRearc = TRUE;
	}
    }

    /*
     * Copy the file if there are downlinks and we send the 
     * original file, but want to rearc it for ourself, or if
     * it's a passthru area.
     */
    if (((tic.SendOrg) && (MustRearc || strlen(tic.Banner))) || (!tic.FileArea)) {
		char *path1 = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
		char *path2 = join_paths(CFG.ticout, sizeof(CFG.ticout), TIC.TicIn.File, sizeof(TIC.TicIn.File));
		if (NULL == path1) {
			WriteError("Unable to join path on %s and %s", TIC.Inbound, TIC.TicIn.File);
			if (NULL != path2) {
				free(path2);
			}
		} else if (NULL == path2) {
			WriteError("Unable to join path on %s and %s", CFG.ticout, TIC.TicIn.File);
			free(path1);
		} else {
			if ((rc = file_cp(path1, path2) == 0)) {
				TIC.SendOrg = TRUE;
			} else {
				WriteError("Copy %s to %s failed: %s", path1, path2, strerror(rc));
			}
			free(path1);
			free(path2);
		}
    }

    if (MustRearc && IsArchive) {
		char *root = getenv("MBSE_ROOT");
		size_t root_len = strlen(root);
		char arc_buffer[32];
		snprintf(arc_buffer, 32, "/tmp/arc%d", (int)getpid());

		char *path = join_paths(root, root_len, arc_buffer, sizeof(arc_buffer));
		if (NULL == path) {
			WriteError("Unable to join path on %s and %s", root, arc_buffer);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}
		if (!checkspace(path, TIC.TicIn.File, UNPACK_FACTOR)) {
			Bad((char *)"Not enough free diskspace left");
			free(path);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}

		if (chdir(path) != 0) {
			WriteError("$Can't change to %s", path);
			free(path);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}

		if (!getarchiver(unarc)) {
			WriteError("Can't get archiver for %s", unarc);
			chdir(TIC.Inbound);
			free(path);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}

		if (strlen(archiver.funarc) == 0) {
			Syslog('!', "No unarc command available");
		} else {
			cmd = xstrcpy(archiver.funarc);
			char *exec_path = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
			if (NULL == exec_path) {
				WriteError("Unable to join paths %s and %s", TIC.Inbound, TIC.TicIn.File);
				free(path);
				clean_tmpwork();
				return 1;
			}
			if (execute_str(cmd, exec_path, (char *)NULL, (char *)"/dev/null", (char *)"/dev/null", (char *)"/dev/null") == 0) {
				UnPacked = TRUE;
			} else {
				chdir(TIC.Inbound);
				Bad((char *)"Archive maybe corrupt");
				free(path);
				free(exec_path);
				clean_tmpwork();
				return 1;
			}
			free(cmd);
			free(exec_path);
		}
		free(path);
    }

    /*
     * Scan file for viri.
     */
    if (tic.VirScan) {
		char *path = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
		if (NULL == path) {
			WriteError("Unable to join paths %s and %s", TIC.Inbound, TIC.TicIn.File);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}
		if (!do_quiet) {
			printf("Virscan   \b\b\b\b\b\b\b\b\b\b");
			fflush(stdout);
		}

		if (VirScanFile(path)) {
			chdir(TIC.Inbound);
			Bad((char *)"Possible virus found!");
			free(path);
			tidy_qualify(&qal);
			clean_tmpwork();
			return 1;
		}

		if (!do_quiet) {
			printf("Checking  \b\b\b\b\b\b\b\b\b\b");
			fflush(stdout);
		}

    }

    if (tic.FileId && tic.FileArea && IsArchive) {
		char *root = getenv("MBSE_ROOT");
		size_t root_len = strlen(root);
		if (UnPacked) {
			char arc_buffer[32];
			snprintf(arc_buffer, 32, "/tmp/arc%d", (int)getpid());
			char *path = join_paths(root, root_len, arc_buffer, sizeof(arc_buffer));
			if (NULL == path) {
				WriteError("Unable to join paths %s and %s", root, arc_buffer);
			} else {
				if (getfilecase(path, (char *)"FILE_ID.DIZ")) {
					Syslog('f', "Found a FILE_ID.DIZ");
				} else {
					Syslog('f', "Didn't find a FILE_ID.DIZ");
				}
				free(path);
			}
		} else {
			if (!getarchiver(unarc)) {
				chdir(TIC.Inbound);
			} else {
				cmd = xstrcpy(archiver.iunarc);

				if (cmd == NULL) {
					WriteError("No unarc command available");
				} else {
					char *path = join_paths(root, root_len, "/tmp", sizeof("/tmp"));
					if (NULL == path) {
						WriteError("Unable to join paths %s and %s", root, "/tmp");
					} else {
						chdir(path);
						free(path);
						char *tic_file = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
						if (NULL == tic_file) {
							WriteError("Unable to join paths %s and %s", TIC.Inbound, TIC.TicIn.File);
						} else {
							size_t len = strlen(tic_file) + 20;
							char *tmp = (char *)calloc(len, sizeof(char));
							if (NULL == tmp) {
								WriteError("Memory allocation error when creating space to hold %s and FILE_ID.DIZ", tic_file);
							} else {
								snprintf(tmp, len, "%s FILE_ID.DIZ", tic_file);
								if (execute_str(cmd, tmp, (char *)NULL, (char *)"/dev/null", (char *)"/dev/null", (char *)"/dev/null")) {
									snprintf(tmp, len, "%s file_id.diz", tic_file);
									execute_str(cmd, tmp, (char *)NULL, (char *)"/dev/null", (char *)"/dev/null", (char *)"/dev/null");
								}
								free(tmp);
							}
							free(tic_file);
						}
					}
					free(cmd);
				}
			} /* if getarchiver */
		} /* if not unpacked */
    } /* if need FILE_ID.DIZ and not passthru */

    /*
     * Create internal file description, priority is FILE_ID.DIZ,
     * 2nd LDesc, and finally the standard description.
     */
    if (!Get_File_Id()) {
	if (TIC.TicIn.TotLDesc > 2) {
	    for (i = 0; i < TIC.TicIn.TotLDesc; i++) {
		strncpy(TIC.File_Id[i], TIC.TicIn.LDesc[i], 48);
	    }
	    TIC.File_Id_Ct = TIC.TicIn.TotLDesc;
	} else {
	    /*
	     * Format the description line (max 255 chars) in parts of 48 characters.
	     */
	    if (strlen(TIC.TicIn.Desc) <= 48) {
		strcpy(TIC.File_Id[0], TIC.TicIn.Desc);
		TIC.File_Id_Ct++;
	    } else {
		memset(&TDesc, 0, sizeof(TDesc));
		strcpy(TDesc, TIC.TicIn.Desc);
		while (strlen(TDesc) > 48) {
		    j = 48;
		    while ((TDesc[j] != ' ') && (j > 0))
			j--;
		    if (j == 0) {
			Syslog('f', "Panic, no spaces");
			j = 47;
		    }
		    strncpy(TIC.File_Id[TIC.File_Id_Ct], TDesc, j);
		    Syslog('f', "%2d/%2d: \"%s\"", TIC.File_Id_Ct, j, TIC.File_Id[TIC.File_Id_Ct]);
		    TIC.File_Id_Ct++;
		    k = strlen(TDesc);
		    j++; /* Correct space */
		    for (i = 0; i <= k; i++, j++)
			TDesc[i] = TDesc[j];
		    if (TIC.File_Id_Ct == 23)
			break;
		}
		memcpy(TIC.File_Id[TIC.File_Id_Ct], TDesc, 48);
		Syslog('f', "%2d/%2d: \"%s\"", TIC.File_Id_Ct, strlen(TIC.File_Id[TIC.File_Id_Ct]), TIC.File_Id[TIC.File_Id_Ct]);
		TIC.File_Id_Ct++;
	    }
	}
    } /* not get FILE_ID.DIZ */

    /*
     * Now check if other (older) ticfiles point to this file,
     * if found mark it to purge later.
     */
    for (topl = *opl; topl; topl = topl->next) {
	if ((strcmp(topl->Area, TIC.TicIn.Area) == 0) && (strcmp(topl->FileName, TIC.TicIn.File) == 0)) {
	    topl->Purged = TRUE;
	}
    }

    /*
     * Rearc file if it is an unpacked archive.
     */
    if ((MustRearc) && (UnPacked) && (tic.FileArea)) {
	if (Rearc(tic.Convert)) {
	    /*
	     * Get new filesize for import and announce
	     */
		char *path = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.NewFile, sizeof(TIC.NewFile));
		if (NULL == path) {
			WriteError("Rearc failed, memory allocation error");
		} else {
			TIC.FileSize = file_size(path);
			T_File.Size = TIC.FileSize;
			T_File.SizeKb = TIC.FileSize / 1024;
			/*
			* Calculate the CRC if we must send the new archived file.
			*/
			if (!TIC.SendOrg) {
				ReCalcCrc(path);
			}
			free(path);
		}
	} else {
	    WriteError("Rearc failed");
	} /* if Rearc() */
    }

    /*
     * Change banner if needed.
     */
    if ((strlen(tic.Banner)) && IsArchive) {
		cmd = xstrcpy(archiver.barc);
		if ((cmd == NULL) || (!strlen(cmd))) {
			Syslog('+', "No banner command for %s", archiver.name);
		} else {
			char *path = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.NewFile, sizeof(TIC.NewFile));
			if (NULL == path) {
				WriteError("Unable to join paths %s and %s in banner command", TIC.Inbound, TIC.NewFile);
			} else {
				char *root = getenv("MBSE_ROOT");
				size_t root_len = strlen(root);

				char etc_buff[sizeof(tic.Banner) + 6];
				snprintf(etc_buff, sizeof(etc_buff), "/etc/%s", tic.Banner);
				char *banner_path = join_paths(root, root_len, etc_buff, sizeof(etc_buff));
				if (NULL == banner_path) {
					WriteError("Unable to join paths %s and %s in banner command", root, etc_buff);
				} else {
					if (execute_str(cmd, path, (char *)NULL, banner_path, (char *)"/dev/null", (char *)"/dev/null")) {
						WriteError("Changing the banner failed");
					} else {
						Syslog('+', "New banner %s", tic.Banner);
						TIC.FileSize = file_size(path);
						T_File.Size = TIC.FileSize;
						T_File.SizeKb = TIC.FileSize / 1024;
						ReCalcCrc(path);
						DidBanner = TRUE;
					}
					free(banner_path);
				}
				free(path);
			}
		}
    }
    clean_tmpwork();
    chdir(TIC.Inbound);

    /*
     * If the file is converted, we set the date of the original
     * received file as the file creation date.
     */

	char *path_tmp = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.NewFile, sizeof(TIC.NewFile));
	if (NULL == path_tmp) {
		WriteError("Unable to join paths %s and %s in creation date check", TIC.Inbound, TIC.NewFile);
	} else {
		if ((MustRearc || DidBanner) && CFG.ct_KeepDate) {
			if ((tic.Touch) && (tic.FileArea)) {
				ut.actime = mktime(localtime(&TIC.FileDate));
				ut.modtime = mktime(localtime(&TIC.FileDate));
				utime(path_tmp, &ut);
				Syslog('-', "Restamp filedate %s to %s", path_tmp, rfcdate(ut.modtime));
			}
		}
		/*
		* Now make sure the file timestamp is updated. The file may be restamped,
		* altered by banners etc.
		*/
		TIC.FileDate = file_time(path_tmp);
		free(path_tmp);
	}

    /*
     * If not passthru, import in the BBS.
     */
    if (tic.FileArea) {

	Syslog('+', "Import: %s (%s) Area: %s", TIC.NewFile, TIC.NewFullName, TIC.TicIn.Area);
	BBS_Imp = Add_BBS(&qal);

	if (!BBS_Imp) {
	    Bad((char *)"File Import Error");
	    tidy_qualify(&qal);
	    clean_tmpwork();
	    return 1;
	}
    }

    chdir(TIC.Inbound);

    /*
     * Create file announce record
     */
    if (tic.FileArea) {
	if (strlen(TIC.TicIn.Magic))
	    magic_update(TIC.TicIn.Magic, TIC.NewFile);
	else
	    Magic_UpDateAlias();

	for (i = 0; i < TIC.File_Id_Ct; i++)
	    strncpy(T_File.LDesc[i], TIC.File_Id[i], 48);
	T_File.TotLdesc = TIC.File_Id_Ct;
	T_File.Announce = tic.Announce;
	memccpy(T_File.Name, TIC.NewFile, '\0', 12);
	memccpy(T_File.LName, TIC.NewFullName, '\0', 80);
	T_File.Fdate = TIC.FileDate;
	Add_ToBeRep(T_File);
    }

    if (TIC.SendOrg && !tic.FileArea) {
	/*
	 * If it's a passthru area we don't need the
	 * file in the inbound anymore so it can be
	 * deleted.
	 */
		char *path = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicIn.File, sizeof(TIC.TicIn.File));
		if (NULL == path) {
			WriteError("Unable to join paths %s and %s in passthru check", TIC.Inbound, TIC.TicIn.File);
		} else {
			if (file_rm(path) == 0)
				Syslog('f', "Deleted %s", path);
			free(path);
		}
    }

    if (DownLinks) {
	First = TRUE;

	/*
	 * Add all our system aka's to the seenby lines in the same zone,
	 * omit aka's already in the seenby list.
	 */
	for (i = 0; i < 39; i++) {
	    if (CFG.akavalid[i] && (tic.Aka.zone == CFG.aka[i].zone)) {
		p_from = fido2faddr(CFG.aka[i]);
		if (! in_list(p_from, sbl, TRUE)) {
		    if (CFG.aka[i].point)
			snprintf(sbe, 24, "%u:%u/%u.%u", CFG.aka[i].zone, CFG.aka[i].net, CFG.aka[i].node, CFG.aka[i].point);
		    else
			snprintf(sbe, 24, "%u:%u/%u", CFG.aka[i].zone, CFG.aka[i].net, CFG.aka[i].node);
		    fill_list(sbl, sbe, NULL);
		}
		tidy_faddr(p_from);
	    }
	}

	/*
	 * Add seen-by lines for all systems that will receive this file.
	 */
	for (tmpq = qal; tmpq; tmpq = tmpq->next) {
	    if (tmpq->send) {
		if (CFG.aka[i].point)
		    snprintf(sbe, 24, "%u:%u/%u.%u", tmpq->aka.zone, tmpq->aka.net, tmpq->aka.node, tmpq->aka.point);
		else
		    snprintf(sbe, 24, "%u:%u/%u", tmpq->aka.zone, tmpq->aka.net, tmpq->aka.node);
		fill_list(sbl, sbe, NULL);
	    }
	}
	uniq_list(sbl);
	sort_list(sbl);
	
	/*
	 * Now forward this file to the qualified downlinks.
	 */
	for (tmpq = qal; tmpq; tmpq = tmpq->next) {
	    if (tmpq->send) {
		ForwardFile(tmpq->aka, *sbl);
		tic_out++;
	    }
	}
    }

    Magic_ExecCommand();
    Magic_CopyFile();
    Magic_UnpackFile();
    Magic_AdoptFile();


	path_tic = join_paths(TIC.Inbound, sizeof(TIC.Inbound), TIC.TicName, sizeof(TIC.TicName));
	if (NULL == path_tic) {
		WriteError("$Can't delete %s/%s, allocation error", TIC.Inbound, TIC.TicName);
	} else {
		if (unlink(path_tic)) {
			WriteError("$Can't delete %s", path_tic);
		}
		free(path_tic);
	}

    tidy_qualify(&qal);
    return 0;
}


