from __future__ import print_function # Py2 compat
from collections import namedtuple
import sys

# These define the structure of the history, and correspond to diff output with
# lines that start with a space, a + and a - respectively.
Keep = namedtuple('Keep', ['line'])
Insert = namedtuple('Insert', ['line'])
Remove = namedtuple('Remove', ['line'])

# See frontier in myers_diff
Frontier = namedtuple('Frontier', ['x', 'history'])

def myers_diff(a_lines, b_lines):
    """
    An implementation of the Myers diff algorithm.
    See http://www.xmailserver.org/diff2.pdf
    """
    # This marks the farthest-right point along each diagonal in the edit
    # graph, along with the history that got it there
    frontier = {1: Frontier(0, [])}

    def one(idx):
        """
        The algorithm Myers presents is 1-indexed; since Python isn't, we
        need a conversion.
        """
        return idx - 1

    a_max = len(a_lines)
    b_max = len(b_lines)
    for d in range(0, a_max + b_max + 1):
        for k in range(-d, d + 1, 2):
            # This determines whether our next search point will be going down
            # in the edit graph, or to the right.
            #
            # The intuition for this is that we should go down if we're on the
            # left edge (k == -d) to make sure that the left edge is fully
            # explored.
            #
            # If we aren't on the top (k != d), then only go down if going down
            # would take us to territory that hasn't sufficiently been explored
            # yet.
            go_down = (k == -d or 
                    (k != d and frontier[k - 1].x < frontier[k + 1].x))

            # Figure out the starting point of this iteration. The diagonal
            # offsets come from the geometry of the edit grid - if you're going
            # down, your diagonal is lower, and if you're going right, your
            # diagonal is higher.
            if go_down:
                old_x, history = frontier[k + 1]
                x = old_x
            else:
                old_x, history = frontier[k - 1]
                x = old_x + 1

            # We want to avoid modifying the old history, since some other step
            # may decide to use it.
            history = history[:]
            y = x - k

            # We start at the invalid point (0, 0) - we should only start building
            # up history when we move off of it.
            if 1 <= y <= b_max and go_down:
                history.append(Insert(b_lines[one(y)]))
            elif 1 <= x <= a_max:
                history.append(Remove(a_lines[one(x)]))

            # Chew up as many diagonal moves as we can - these correspond to common lines,
            # and they're considered "free" by the algorithm because we want to maximize
            # the number of these in the output.
            while x < a_max and y < b_max and a_lines[one(x + 1)] == b_lines[one(y + 1)]:
                x += 1
                y += 1
                history.append(Keep(a_lines[one(x)]))

            if x >= a_max and y >= b_max:
                # If we're here, then we've traversed through the bottom-left corner,
                # and are done.
                return history
            else:
                frontier[k] = Frontier(x, history)

    assert False, 'Could not find edit script'

def main():
    try:
        _, a_file, b_file = sys.argv
    except ValueError:
        print(sys.argv[0], '<FILE>', '<FILE>')
        return 1

    with open(a_file) as a_handle:
        a_lines = [line.rstrip() for line in a_handle]

    with open(b_file) as b_handle:
        b_lines = [line.rstrip() for line in b_handle]

    diff = myers_diff(a_lines, b_lines)
    for elem in diff:
        if isinstance(elem, Keep):
            print(' ' + elem.line)
        elif isinstance(elem, Insert):
            print('+' + elem.line)
        else:
            print('-' + elem.line)

if __name__ == '__main__':
    sys.exit(main())
