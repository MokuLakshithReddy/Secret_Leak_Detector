import { execFile } from 'child_process';
import { promisify } from 'util';
import { GitHistoryEngine, GitSearchResult } from './gitHistoryEngine';

// execFile (argument array) keeps untrusted values out of a shell, preventing
// command injection via the credential being traced.
const execFileAsync = promisify(execFile);

export interface GitTimelineEvent {
  eventType: 'INTRODUCED' | 'MODIFIED' | 'REMOVED' | 'MERGED_IN';
  commitSha: string;
  authorName: string;
  authorEmail: string;
  date: string;
  commitMessage: string;
  isMergeCommit: boolean;
  parentShas: string[];
  branches: string[];
  exposureDaysSoFar: number;
}

export interface GitGraphNode {
  id: string;
  shortHash: string;
  label: string;
  author: string;
  date: string;
  eventType: 'INTRODUCED' | 'MODIFIED' | 'REMOVED' | 'MERGED_IN';
  isMerge: boolean;
  branches: string[];
  isHead: boolean;
  hasSecret: boolean;
}

export interface GitGraphEdge {
  from: string;
  to: string;
  relation?: 'DIRECT_PARENT' | 'EVENT_SEQUENCE';
}

export interface GitExposureGraph {
  nodes: GitGraphNode[];
  edges: GitGraphEdge[];
  summary: {
    totalExposedCommits: number;
    introducedCommit: string;
    removedCommit?: string;
    durationDays: number;
    branchesContaminated: string[];
    isPushedToRemote: boolean | 'UNKNOWN';
  };
}

export interface ExposureTimelineReport {
  secretRedacted: string;
  events: GitTimelineEvent[];
  firstIntroducedDate?: string;
  removalDate?: string;
  totalExposureDays: number;
  currentStatus: 'ACTIVE_IN_HEAD' | 'REMOVED_FROM_HEAD_PRESENT_IN_HISTORY' | 'CLEAN_UNCOMMITTED' | 'NOT_FOUND' | 'PARTIAL_HISTORY' | 'SEARCH_INCOMPLETE' | 'ERROR';
  reachableBranches: string[];
  isPushedToRemote: boolean | 'UNKNOWN';
  timelineAscii: string;
  graph: GitExposureGraph;
  isPartialHistory?: boolean;
}

export class GitTimelineEngine {
  private workspaceRoot: string;
  private gitHistory: GitHistoryEngine;

  constructor(workspaceRoot: string, gitHistory?: GitHistoryEngine) {
    this.workspaceRoot = workspaceRoot;
    this.gitHistory = gitHistory || new GitHistoryEngine(workspaceRoot);
  }

  public async buildTimeline(secret: string, redactedSecret: string, maxCommits = 0): Promise<ExposureTimelineReport> {
    const lines: string[] = [];
    let searchResult: GitSearchResult | undefined;
    let commitShas: string[] = [];
    let failedTimelineMetadataCount = 0;
    let timelineMetadataError: string | undefined;

    try {
      const isGit = await this.gitHistory.isGitRepo();
      if (!isGit) {
        throw new Error(`Directory is not a Git repository: ${this.workspaceRoot}`);
      }

      searchResult = await this.gitHistory.findCommitsContainingSecretResult(secret, maxCommits);
      commitShas = searchResult.commitShas;

      if (searchResult.status === 'ERROR' || searchResult.status === 'SEARCH_INCOMPLETE') {
        const matchesNote =
          searchResult.commitShas.length > 0
            ? ` (${searchResult.commitShas.length} matching commit(s) discovered before failure)`
            : '';
        return {
          secretRedacted: redactedSecret,
          events: [],
          totalExposureDays: 0,
          currentStatus: searchResult.status,
          reachableBranches: [],
          isPushedToRemote: false,
          timelineAscii: `Git history search was incomplete: ${searchResult.error || 'operational failure'}${matchesNote}`,
          graph: {
            nodes: [],
            edges: [],
            summary: {
              totalExposedCommits: searchResult.commitShas.length,
              introducedCommit: searchResult.commitShas[0] || '',
              durationDays: 0,
              branchesContaminated: [],
              isPushedToRemote: false,
            },
          },
          isPartialHistory: searchResult.isPartialHistory,
        };
      }

      commitShas = searchResult.commitShas;
      if (commitShas.length === 0) {
        const inWorkingTree = await this.gitHistory.isSecretInWorkingTree(secret);
        if (inWorkingTree) {
          return {
            secretRedacted: redactedSecret,
            events: [],
            totalExposureDays: 0,
            currentStatus: 'CLEAN_UNCOMMITTED',
            reachableBranches: ['working-tree'],
            isPushedToRemote: false,
            timelineAscii: 'Credential exists only in uncommitted local working tree.',
            graph: {
              nodes: [],
              edges: [],
              summary: {
                totalExposedCommits: 0,
                introducedCommit: '',
                durationDays: 0,
                branchesContaminated: ['working-tree'],
                isPushedToRemote: false,
              },
            },
          };
        } else if (searchResult.status === 'PARTIAL_HISTORY') {
          return {
            secretRedacted: redactedSecret,
            events: [],
            totalExposureDays: 0,
            currentStatus: 'PARTIAL_HISTORY',
            reachableBranches: [],
            isPushedToRemote: false,
            timelineAscii: `Credential was not found in latest ${maxCommits} commit(s), but repository history search was limited.`,
            graph: {
              nodes: [],
              edges: [],
              summary: {
                totalExposedCommits: 0,
                introducedCommit: '',
                durationDays: 0,
                branchesContaminated: [],
                isPushedToRemote: false,
              },
            },
          };
        } else {
          return {
            secretRedacted: redactedSecret,
            events: [],
            totalExposureDays: 0,
            currentStatus: 'NOT_FOUND',
            reachableBranches: [],
            isPushedToRemote: false,
            timelineAscii: 'Credential was not found in Git history or working tree.',
            graph: {
              nodes: [],
              edges: [],
              summary: {
                totalExposedCommits: 0,
                introducedCommit: '',
                durationDays: 0,
                branchesContaminated: [],
                isPushedToRemote: false,
              },
            },
          };
        }
      }

      // Fetch metadata for each commit without passing secret in argv
      failedTimelineMetadataCount = 0;
      timelineMetadataError = undefined;

      for (const sha of commitShas) {
        try {
          const { stdout: commitInfo } = await (this.gitHistory as any).execGit(
            ['log', '-1', '--format=%H|%P|%an|%ae|%ad|%s', '--date=iso', sha],
            { encoding: 'utf8' }
          );
          if (commitInfo.trim()) {
            lines.push(commitInfo.trim());
          } else {
            failedTimelineMetadataCount++;
          }
        } catch (tmErr: any) {
          failedTimelineMetadataCount++;
          timelineMetadataError = tmErr?.message || String(tmErr);
        }
      }

      // Sort commits chronologically ascending (oldest to newest)
      lines.sort((a, b) => {
        const dateA = a.split('|')[4] || '';
        const dateB = b.split('|')[4] || '';
        return new Date(dateA).getTime() - new Date(dateB).getTime();
      });
    } catch (err: any) {
      return {
        secretRedacted: redactedSecret,
        events: [],
        totalExposureDays: 0,
        currentStatus: 'ERROR',
        reachableBranches: ['local'],
        isPushedToRemote: false,
        timelineAscii: `Git history timeline query failed: ${err?.message || String(err)}`,
        graph: {
          nodes: [],
          edges: [],
          summary: {
            totalExposedCommits: 0,
            introducedCommit: '',
            durationDays: 0,
            branchesContaminated: ['local'],
            isPushedToRemote: false,
          },
        },
      };
    }

    if (lines.length === 0) {
      if (commitShas.length > 0) {
        return {
          secretRedacted: redactedSecret,
          events: [],
          totalExposureDays: 0,
          currentStatus: 'SEARCH_INCOMPLETE',
          reachableBranches: [],
          isPushedToRemote: false,
          timelineAscii: `Credential was detected in ${commitShas.length} commit(s), but commit metadata retrieval failed.`,
          graph: {
            nodes: [],
            edges: [],
            summary: {
              totalExposedCommits: commitShas.length,
              introducedCommit: commitShas[0] || '',
              durationDays: 0,
              branchesContaminated: [],
              isPushedToRemote: false,
            },
          },
          isPartialHistory: searchResult.isPartialHistory,
        };
      }
      return {
        secretRedacted: redactedSecret,
        events: [],
        totalExposureDays: 0,
        currentStatus: 'NOT_FOUND',
        reachableBranches: [],
        isPushedToRemote: false,
        timelineAscii: 'Credential was not found in Git history or working tree.',
        graph: {
          nodes: [],
          edges: [],
          summary: {
            totalExposedCommits: 0,
            introducedCommit: '',
            durationDays: 0,
            branchesContaminated: [],
            isPushedToRemote: false,
          },
        },
        isPartialHistory: searchResult.isPartialHistory,
      };
    }

    const events: GitTimelineEvent[] = [];
    let firstDate: Date | undefined;
    let allReachableBranches = new Set<string>();
    let isPushedToRemote: boolean | 'UNKNOWN';
    let pushedConfirmed = false;
    let branchLookupFailed = false;
    let branchLookupError: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      const [sha, parentsStr, author, email, dateStr, ...msgParts] = lines[i].split('|');
      const message = msgParts.join('|');
      const parentShas = (parentsStr || '').split(' ').filter(Boolean);
      const isMergeCommit = parentShas.length > 1;

      // Branches containing this commit
      let branches: string[] = [];
      try {
        const { stdout: bOut } = await execFileAsync(
          'git',
          ['branch', '-a', '--contains', sha],
          { cwd: this.workspaceRoot }
        );
        branches = bOut
          .split('\n')
          .map((b) => b.trim().replace(/^[\*\s]+/, ''))
          .filter(Boolean);
      } catch (err: any) {
        branchLookupFailed = true;
        branchLookupError = err?.message || String(err);
        branches = [];
      }

      branches.forEach((b) => {
        allReachableBranches.add(b);
        if (b.startsWith('remotes/') || b.startsWith('origin/')) {
          pushedConfirmed = true;
        }
      });

      const commitDate = new Date(dateStr);
      if (!firstDate) firstDate = commitDate;

      const exposureDaysSoFar = Math.max(
        0,
        Math.round((commitDate.getTime() - firstDate.getTime()) / (1000 * 60 * 60 * 24))
      );

      let eventType: GitTimelineEvent['eventType'] = 'MODIFIED';
      if (i === 0) {
        eventType = 'INTRODUCED';
      } else if (i === lines.length - 1) {
        let inHead: boolean | 'UNKNOWN' = 'UNKNOWN';
        try {
          inHead = await this.gitHistory.isSecretInHead(secret);
        } catch {
          inHead = 'UNKNOWN';
        }
        eventType = inHead === true ? 'MODIFIED' : inHead === false ? 'REMOVED' : 'MODIFIED';
      } else if (isMergeCommit) {
        eventType = 'MERGED_IN';
      }

      events.push({
        eventType,
        commitSha: sha,
        authorName: author,
        authorEmail: email,
        date: dateStr,
        commitMessage: message,
        isMergeCommit,
        parentShas,
        branches,
        exposureDaysSoFar,
      });
    }

    if (pushedConfirmed) {
      isPushedToRemote = true;
    } else if (branchLookupFailed) {
      isPushedToRemote = 'UNKNOWN';
    } else {
      isPushedToRemote = false;
    }

    const lastEvent = events[events.length - 1];
    let isPresentInHead: boolean | 'UNKNOWN' = 'UNKNOWN';
    let headCheckFailed = false;
    try {
      isPresentInHead = await this.gitHistory.isSecretInHead(secret);
    } catch {
      isPresentInHead = 'UNKNOWN';
      headCheckFailed = true;
    }

    const currentStatus: ExposureTimelineReport['currentStatus'] =
      (failedTimelineMetadataCount > 0 || headCheckFailed || branchLookupFailed)
        ? 'SEARCH_INCOMPLETE'
        : isPresentInHead
        ? 'ACTIVE_IN_HEAD'
        : events.length > 0
        ? 'REMOVED_FROM_HEAD_PRESENT_IN_HISTORY'
        : 'CLEAN_UNCOMMITTED';

    const firstDateMs = firstDate ? firstDate.getTime() : Date.now();
    const lastDateMs =
      currentStatus === 'ACTIVE_IN_HEAD'
        ? Date.now()
        : new Date(lastEvent?.date || Date.now()).getTime();

    const totalExposureDays = Math.max(
      0,
      Math.round((lastDateMs - firstDateMs) / (1000 * 60 * 60 * 24))
    );

    // Format ASCII visual timeline
    let timelineAscii = `\nCommit-Level Exposure Timeline for: ${redactedSecret}\n`;
    timelineAscii += '═'.repeat(68) + '\n';

    events.forEach((ev, idx) => {
      const tag =
        ev.eventType === 'INTRODUCED'
          ? '🚨 INTRODUCED'
          : ev.eventType === 'REMOVED'
          ? '✅ REMOVED FROM HEAD'
          : ev.isMergeCommit
          ? '🔀 MERGE COMMIT'
          : '✏️  MODIFIED';

      timelineAscii += `[${ev.date.substring(0, 10)}] ${tag}\n`;
      timelineAscii += `   Commit:   ${ev.commitSha.substring(0, 8)} by ${ev.authorName} <${ev.authorEmail}>\n`;
      timelineAscii += `   Message:  "${ev.commitMessage}"\n`;
      timelineAscii += `   Branches: ${ev.branches.slice(0, 3).join(', ')}${ev.branches.length > 3 ? '...' : ''}\n`;
      if (idx < events.length - 1) {
        timelineAscii += `   │\n   │ (${events[idx + 1].exposureDaysSoFar - ev.exposureDaysSoFar} days later)\n   ▼\n`;
      }
    });

    timelineAscii += '═'.repeat(68) + '\n';
    timelineAscii += `Current Status:     ${currentStatus}\n`;
    if (failedTimelineMetadataCount > 0) {
      timelineAscii += `Metadata Quality:   INCOMPLETE (${failedTimelineMetadataCount} of ${commitShas.length} metadata requests failed: ${timelineMetadataError})\n`;
    }
    if (headCheckFailed) {
      timelineAscii += `HEAD Verification:  INCOMPLETE (operational error during HEAD inspection)\n`;
    }
    if (branchLookupFailed) {
      timelineAscii += `Branch Inspection:  INCOMPLETE (operational error during branch reachability query: ${branchLookupError})\n`;
    }
    if (searchResult.isPartialHistory) {
      timelineAscii += `History Coverage:   PARTIAL (limited to ${maxCommits} commits; earlier history uninspected)\n`;
    }
    timelineAscii += `Total Exposure:     ${totalExposureDays} days\n`;
    const nodes: GitGraphNode[] = events.map((ev, idx) => ({
      id: ev.commitSha,
      shortHash: ev.commitSha.substring(0, 8),
      label: `${ev.eventType}: ${ev.commitMessage.substring(0, 30)}`,
      author: `${ev.authorName} <${ev.authorEmail}>`,
      date: ev.date,
      eventType: ev.eventType,
      isMerge: ev.isMergeCommit,
      branches: ev.branches,
      isHead: idx === events.length - 1 && currentStatus === 'ACTIVE_IN_HEAD',
      hasSecret: ev.eventType !== 'REMOVED',
    }));

    const edges: GitGraphEdge[] = [];
    for (let i = 0; i < events.length; i++) {
      const ev = events[i];
      let hasDirectParent = false;
      for (const parent of ev.parentShas) {
        if (events.some((e) => e.commitSha === parent)) {
          edges.push({ from: parent, to: ev.commitSha, relation: 'DIRECT_PARENT' });
          hasDirectParent = true;
        }
      }
      // If immediate Git parents are not in the filtered credential event set (due to intervening commits),
      // link with the preceding chronological event and label relation as EVENT_SEQUENCE
      if (!hasDirectParent && i > 0) {
        edges.push({ from: events[i - 1].commitSha, to: ev.commitSha, relation: 'EVENT_SEQUENCE' });
      }
    }

    const graph: GitExposureGraph = {
      nodes,
      edges,
      summary: {
        totalExposedCommits: events.length,
        introducedCommit: events[0]?.commitSha || '',
        removedCommit: currentStatus !== 'ACTIVE_IN_HEAD' ? lastEvent?.commitSha : undefined,
        durationDays: totalExposureDays,
        branchesContaminated: Array.from(allReachableBranches),
        isPushedToRemote,
      },
    };

    return {
      secretRedacted: redactedSecret,
      events,
      firstIntroducedDate: firstDate?.toISOString(),
      removalDate: currentStatus !== 'ACTIVE_IN_HEAD' ? lastEvent?.date : undefined,
      totalExposureDays,
      currentStatus,
      reachableBranches: Array.from(allReachableBranches),
      isPushedToRemote,
      timelineAscii,
      graph,
      isPartialHistory: searchResult.isPartialHistory || failedTimelineMetadataCount > 0,
    };
  }
}
