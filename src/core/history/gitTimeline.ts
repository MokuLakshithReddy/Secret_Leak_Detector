import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

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
    isPushedToRemote: boolean;
  };
}

export interface ExposureTimelineReport {
  secretRedacted: string;
  events: GitTimelineEvent[];
  firstIntroducedDate?: string;
  removalDate?: string;
  totalExposureDays: number;
  currentStatus: 'ACTIVE_IN_HEAD' | 'REMOVED_FROM_HEAD_PRESENT_IN_HISTORY' | 'CLEAN_UNCOMMITTED';
  reachableBranches: string[];
  isPushedToRemote: boolean;
  timelineAscii: string;
  graph: GitExposureGraph;
}

export class GitTimelineEngine {
  private workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

  public async buildTimeline(secret: string, redactedSecret: string): Promise<ExposureTimelineReport> {
    const escaped = secret.replace(/"/g, '\\"');
    let logOutput = '';

    try {
      const { stdout } = await execAsync(
        `git log -S "${escaped}" --all --reverse --format="%H|%P|%an|%ae|%ad|%s" --date=iso`,
        { cwd: this.workspaceRoot, maxBuffer: 15 * 1024 * 1024 }
      );
      logOutput = stdout.trim();
    } catch {
      return {
        secretRedacted: redactedSecret,
        events: [],
        totalExposureDays: 0,
        currentStatus: 'CLEAN_UNCOMMITTED',
        reachableBranches: ['local'],
        isPushedToRemote: false,
        timelineAscii: 'No Git history found for this credential.',
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

    if (!logOutput) {
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
    }

    const lines = logOutput.split('\n').filter((l) => l.trim().length > 0);
    const events: GitTimelineEvent[] = [];
    let firstDate: Date | undefined;
    let allReachableBranches = new Set<string>();
    let isPushedToRemote = false;

    for (let i = 0; i < lines.length; i++) {
      const [sha, parentsStr, author, email, dateStr, ...msgParts] = lines[i].split('|');
      const message = msgParts.join('|');
      const parentShas = (parentsStr || '').split(' ').filter(Boolean);
      const isMergeCommit = parentShas.length > 1;

      // Branches containing this commit
      let branches: string[] = [];
      try {
        const { stdout: bOut } = await execAsync(`git branch -a --contains ${sha}`, {
          cwd: this.workspaceRoot,
        });
        branches = bOut
          .split('\n')
          .map((b) => b.trim().replace(/^[\*\s]+/, ''))
          .filter(Boolean);
      } catch {
        branches = ['main'];
      }

      branches.forEach((b) => {
        allReachableBranches.add(b);
        if (b.startsWith('remotes/') || b.startsWith('origin/')) {
          isPushedToRemote = true;
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
        // Check if secret currently in HEAD
        try {
          await execAsync(`git grep -F -q "${escaped}" HEAD`, { cwd: this.workspaceRoot });
          eventType = 'MODIFIED';
        } catch {
          eventType = 'REMOVED';
        }
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

    const lastEvent = events[events.length - 1];
    let isPresentInHead = false;
    try {
      await execAsync(`git grep -F -q "${escaped}" HEAD`, { cwd: this.workspaceRoot });
      isPresentInHead = true;
    } catch {
      isPresentInHead = false;
    }

    const currentStatus = isPresentInHead
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
      for (const parent of ev.parentShas) {
        if (events.some((e) => e.commitSha === parent)) {
          edges.push({ from: parent, to: ev.commitSha });
        }
      }
      if (edges.length === 0 && i > 0) {
        edges.push({ from: events[i - 1].commitSha, to: ev.commitSha });
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
    };
  }
}
