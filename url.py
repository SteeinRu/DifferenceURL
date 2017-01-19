#!/usr/bin/env python

import argparse
import base64
import copy
import logging
import sys

"""
    DifferenceURL

    Library which shows the difference between several links


    @package     DifferenceURL

    @author      Shamsudin Serderov
    @url         https://www.steein.ru

    @copyright   2017 - Steein Inc
    @version     1.0.0

"""


# -------------------------------------------------------------------------------------------------------


class Error(Exception):
    """ Base exception class. """
    pass


class ParamDiffTypeError(Error):
    """ Raised when an incorrect diff type used. """
    pass


class HostnameParseError(Error):
    """ Raised when unable to parse hostname from URL. """
    pass


# -------------------------------------------------------------------------------------------------------


"""
   Represents difference of 2 URL params with same name.

   TODO(macpd): investigate making this a namedtuple
"""


class DiffEntry(object):
    left_only = 1
    right_only = 2
    both_differ = 3

    left_header_format = '{0}\n< {1}'
    right_header_format = '{0}\n> {1}'

    left_additional_separator = '\n< '
    right_additional_separator = '\n> '

    def __init__(self, name, left_value, right_value, diff_type):
        self._name = name
        self._left_val = list(left_value) if left_value else []
        self._right_val = list(right_value) if right_value else []
        try:
            if self._valid_diff_type(diff_type):
                self._type = diff_type
        except ParamDiffTypeError:
            logging.error("Incorrect diff type: %s", diff_type)
            self._type = self.both_differ

    def _valid_diff_type(self, diff_type):
        if (diff_type != self.left_only and diff_type != self.right_only and
                    diff_type != self.both_differ):
            raise ParamDiffTypeError('%s is not a valid diff type. ', diff_type)
        return True

    @property
    def name(self):
        return self._name

    def __str__(self):
        ret = self._name
        if self._type == self.left_only or self._type == self.both_differ:
            ret = self.left_header_format.format(ret, self.left_additional_separator.join(self._left_val))
        if self._type == self.right_only or self._type == self.both_differ:
            ret = self.right_header_format.format(ret, self.right_additional_separator.join(self._right_val))
        return ret


# -------------------------------------------------------------------------------------------------------

"""
    Object to diff URLs.
    Diffs URLs upon initialization.
"""


class UrlDiffer(object):
    PATH_DELIM = '?'
    PARAM_DELIM = '&'
    NAME_VAL_DELIM = '='
    SCHEME_DELIM = '://'
    UNIX_SLASH = '/'
    URL_ESCAPE_CHAR = '%'
    URL_ESCAPE_SEQ_LEN = 3  # expected length of URL espace sequences, aka len('%25')

    """
        Initializes object and performs URL diffing.
    """

    def __init__(self, left_url, right_url, names_only=False, hostnames=False,
                 url_decode_params=False, case_insensitive=False):
        self._left_url = self._normalize_url(left_url)
        self._right_url = self._normalize_url(right_url)
        self._names_only = names_only
        self._wants_hostname_diff = hostnames
        self._url_decode_params = url_decode_params
        self._case_insensitive = case_insensitive
        self._diffs = []
        self._do_diff()

    def __str__(self):
        ret = []
        for diff in self._diffs:
            if self._names_only:
                ret.append(diff.name)
            else:
                ret.append(str(diff))
        join_delim = '\n' if self._names_only else '\n\n'
        return join_delim.join(ret)

    """
        Strips white space, and removes all chars after #
    """

    def _normalize_url(self, url):
        ret = url.strip()
        if '#' in ret:
            idx = ret.index('#')
            ret = ret[:idx]
        return ret

    """
        Parses the hostname from a URL"
        Finds hostname between scheme and first unix slash.
    """

    def _get_hostname(self, url):
        if self.SCHEME_DELIM in url:
            scheme_idx = url.index(self.SCHEME_DELIM)
            hostname_begin = scheme_idx + len(self.SCHEME_DELIM)
        else:
            hostname_begin = 0

        if self.UNIX_SLASH in url[hostname_begin:]:
            hostname_end = url.index(self.UNIX_SLASH, hostname_begin)
        else:
            hostname_end = hostname_begin + len(url[hostname_begin:])

        return url[hostname_begin:hostname_end]

    """
        Diffs hostnames, if different appends ParamDiffEntry to diffs list.

        Args:
            left: String; left hostname.
            right: String; right hostname.
        Returns:
            Bool; True if different, else False.
    """

    def _diff_hostnames(self, left, right):
        if left == right:
            self._hostnames_differ = False
        else:
            self._hostnames_differ = True
            self._diffs.append(
                DiffEntry(
                    'Hostname',
                    [left],
                    [right],
                    DiffEntry.both_differ
                )
            )

        return self._hostnames_differ

    """
        Returns a dict of the url params.

        Args:
            url: String; URL to get parameter names and values from.
        Returns:
            Dict of parameter names that map to their values.
    """

    def _get_params(self, url):
        param_dict = {}
        if self.PATH_DELIM not in url:
            return param_dict

        params_pos = url.find(self.PATH_DELIM) + 1
        for token in url[params_pos:].split(self.PARAM_DELIM):
            if not token:
                continue
            if '=' not in token:
                token_key = token
                token_value = ''
            else:
                partitioned_param = token.partition(self.NAME_VAL_DELIM)
                token_key = partitioned_param[0]
                token_value = partitioned_param[2]

            if self._url_decode_params:
                token_key = self._url_decode(token_key)
                token_value = self._url_decode(token_value)

            value_list = param_dict.get(token_key, [])
            value_list.append(token_value)
            param_dict[token_key] = value_list

        return param_dict

    """
        Returns a list of the diffence between dicts on key/values.
        First all keys that exist in both URLs are compared, then keys only in the
        left, followed by keys only in the right.

        Args:
            left_param: dict; param name -> values dict of the left URL.
            right_param: dict; param name -> values dict of the right URL.
        Returns:
            List of ParamDiffEntry of differences between the left and right params.
    """

    @staticmethod
    def _diff_params(left_params, right_params):

        diffs = []
        left_key_set = frozenset(left_params.keys())
        right_key_set = frozenset(right_params.keys())
        left_key_diff = left_key_set.difference(right_key_set)
        right_key_diff = right_key_set.difference(left_key_set)
        key_intersection = left_key_set.intersection(right_key_set)

        for common_key in key_intersection:
            left_val_set = set(left_params[common_key])
            right_val_set = set(right_params[common_key])
            left_diff = left_val_set.difference(right_val_set)
            right_diff = right_val_set.difference(left_val_set)
            if left_diff and right_diff:
                diff_type = DiffEntry.both_differ
            elif left_diff:
                diff_type = DiffEntry.left_only
            elif right_diff:
                diff_type = DiffEntry.right_only
            else:
                # if no diff skip to next iteration
                continue
            diffs.append(
                DiffEntry(
                    common_key,
                    left_val_set.difference(right_val_set),
                    right_val_set.difference(left_val_set),
                    diff_type
                )
            )

        for left_key in left_key_diff:
            diffs.append(DiffEntry(
                left_key, left_params[left_key], None, DiffEntry.left_only))

        for right_key in right_key_diff:
            diffs.append(DiffEntry(
                right_key, None, right_params[right_key], DiffEntry.right_only))

        return diffs

    """
        Performs all appropriate diffing operations.
    """

    def _do_diff(self):
        if self._case_insensitive:
            self._left_url, self._right_url = self._left_url.lower(), self._right_url.lower()
        if self._wants_hostname_diff:
            self._left_hostname = self._get_hostname(self._left_url)
            self._right_hostname = self._get_hostname(self._right_url)
            self._diff_hostnames(self._left_hostname, self._right_hostname)
        self._left_params_dict = self._get_params(self._left_url)
        self._right_params_dict = self._get_params(self._right_url)

        if not self._left_params_dict == self._right_params_dict:
            self._diffs.extend(self._diff_params(
                self._left_params_dict,
                self._right_params_dict
            )
            )

    """
        URL decodes provided string.
            Replaces all instances of %NN with the ascii value of hex(NN).

        Args:
            token: String to be decoded.
        Returns:
            String; deocded string.
    """

    def _url_decode(self, token):
        if self.URL_ESCAPE_CHAR not in token:
            return token
        new_token = []
        cur = prev = 0
        cur = token.find(self.URL_ESCAPE_CHAR, prev)
        while cur != -1:
            new_token.append(token[prev:cur])
            decoded_hex_as_bytes = base64.b16decode(
                token[cur + 1:cur + self.URL_ESCAPE_SEQ_LEN], casefold=True)
            new_token.append(decoded_hex_as_bytes.decode())
            prev = cur + self.URL_ESCAPE_SEQ_LEN
            cur = token.find(self.URL_ESCAPE_CHAR, prev)

        new_token.append(token[prev:])
        return ''.join(new_token)

    """
        Returns a deep coy of the left params dict.
    """

    def left_params(self):
        return copy.deepcopy(self._left_params_dict)

    """
        Returns a deep coy of the left params dict.
    """

    def right_params(self):
        return copy.deepcopy(self._right_params_dict)

    """
        Returns True if URLs differ, else false.
    """

    def are_different(self):
        return len(self._diffs) != 0

    # -------------------------------------------------------------------------------------------------------

    @property
    def diff(self):
        return copy.deepcopy(self._diffs)


# -------------------------------------------------------------------------------------------------------

"""
    Parses args, inits and prints differ, and exits with appropriate value.

    TODO(macpd): provide option for second diff delimeter.  This would allow one to diff multivalued param values.
    TODO(macpd): provide verbosity option
"""


def launcher():
    arg_parser = argparse.ArgumentParser(
        version='1.0.0',

        description='It shows the difference between the two references',
        epilog='This is a small library that throws everything after the # sign '
               'https://github.com/SteeinSource/DifferenceURL',
        add_help=True
    )
    # argument --hostname
    arg_parser.add_argument('--hostname', default=False, required=False,
                            help='also diff URL hostname', action='store_true', dest='diff_hostname'
                            )

    # argument --names
    arg_parser.add_argument('--names', '-n', default=False, required=False,
                            help='only diff URL parameter names.', action='store_true', dest='names_only'
                            )

    # argument --decode
    arg_parser.add_argument('--decode', '-d', default=False, required=False,
                            help='URL decode parameter names and values (if applicable). Decoded params will be used '
                                 'for comparison and printing.',
                            action='store_true', dest='decode_params'
                            )

    # argument "left_url"
    arg_parser.add_argument('left_url', type=str,
                            help='URL to diff against.  Logically handled as the left argument of diff.',
                            metavar='<left URL>')

    # argument "right_url"
    arg_parser.add_argument('right_url', type=str,
                            help='URL to diff against.  Logically handled as the right argument of diff.',
                            metavar='<right URL>', nargs='?', default=''
                            )

    # argument --quiet
    arg_parser.add_argument('--quiet', '-q', action='store_true',
                            help='suppress output and return non-zero if URLs differ.',
                            default=False, required=False
                            )

    # argument --case_insensitive
    arg_parser.add_argument('--case_insensitive', '-i', action='store_true',
                            help='Perform case insensitive diff. NOTE: this converts all input to lowercase.',
                            default=False, required=False
                            )

    # parser argument
    args = arg_parser.parse_args()

    differ = UrlDiffer(args.left_url,
                       args.right_url,
                       names_only=args.names_only,
                       hostnames=args.diff_hostname,
                       url_decode_params=args.decode_params,
                       case_insensitive=args.case_insensitive
                       )

    if not args.quiet:
        sys.stdout.write('%s\n' % differ)

    sys.exit(1 if differ.are_different() else 0)


if __name__ == '__main__':
    launcher()
