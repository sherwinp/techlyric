//------------------------------------------------------------------------------
// <copyright file="PersonalizationProviderHelper.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace AccessProviders
{
    using System;
    using System.Collections;
    using System.Globalization;
    using System.Web.Util;
    using System.Web.UI.WebControls.WebParts;

    internal static class PersonalizationProviderHelper
    {
        internal static string[] CheckAndTrimNonEmptyStringEntries(string[] array, string paramName,
                                                                   bool throwIfArrayIsNull, bool checkCommas,
                                                                   int lengthToCheck)
        {
            if (array == null)
            {
                if (throwIfArrayIsNull)
                {
                    throw new ArgumentNullException(paramName);
                }
                else
                {
                    return null;
                }
            }
            if (array.Length == 0)
            {
                throw new ArgumentException("Empty Collection", paramName);
            }

            string[] result = null;

            for (int i = 0; i < array.Length; i++)
            {
                string str = array[i];
                string trimmedStr = (str == null) ? null : str.Trim();
                if (String.IsNullOrEmpty(trimmedStr))
                {
                    throw new ArgumentException("Null or empty string entries", paramName);
                }
                if (checkCommas && trimmedStr.IndexOf(',') != -1)
                {
                    throw new ArgumentException("Cannot have comma in string", paramName);
                }
                if (lengthToCheck > -1 && trimmedStr.Length > lengthToCheck)
                {
                    throw new ArgumentException("Trimmed entry value exceeds maximum length", paramName);
                }

                if (str.Length != trimmedStr.Length)
                {
                    if (result == null)
                    {
                        result = new string[array.Length];
                        Array.Copy(array, result, i);
                    }
                }

                if (result != null)
                {
                    result[i] = trimmedStr;
                }
            }

            return ((result != null) ? result : array);
        }

        internal static string CheckAndTrimString(string paramValue, string paramName,
                                                  bool throwIfNull, int lengthToCheck)
        {
            if (paramValue == null)
            {
                if (throwIfNull)
                {
                    throw new ArgumentNullException(paramName);
                }
                return null;
            }
            string trimmedValue = paramValue.Trim();
            if (trimmedValue.Length == 0)
            {
                throw new ArgumentException("Cannot be empty string after trimming", paramName);
            }
            if (lengthToCheck > -1 && trimmedValue.Length > lengthToCheck)
            {
                throw new ArgumentException("Trimmed string exceeds maximum length", paramName);
            }
            return trimmedValue;
        }

        internal static string CheckAndTrimStringWithoutCommas(string paramValue, string paramName)
        {
            string trimmedValue = CheckAndTrimString(paramValue, paramName, true, -1);
            if (trimmedValue.IndexOf(',') != -1)
            {
                throw new ArgumentException("Cannot have comma in string", paramName);
            }
            return trimmedValue;
        }

        internal static void CheckOnlyOnePathWithUsers(string[] paths, string[] usernames)
        {
            if (usernames != null && usernames.Length > 0 &&
                paths != null && paths.Length > 1)
            {
                throw new ArgumentException("More than one path", "paths");
            }
        }

        internal static void CheckNegativeInteger(int paramValue, string paramName)
        {
            if (paramValue < 0)
            {
                throw new ArgumentException("Must be non negative", paramName);
            }
        }

        internal static void CheckNegativeReturnedInteger(int returnedValue, string methodName)
        {
            if (returnedValue < 0)
            {
                throw new ArgumentException("Unexpected return value");
            }
        }

        internal static void CheckNullEntries(ICollection array, string paramName)
        {
            if (array == null)
            {
                throw new ArgumentNullException(paramName);
            }
            if (array.Count == 0)
            {
                throw new ArgumentException("Empty collection", paramName);
            }
            foreach (object item in array)
            {
                if (item == null)
                {
                    throw new ArgumentException("Null entries in collection", paramName);
                }
            }
        }

        internal static void CheckPageIndexAndSize(int pageIndex, int pageSize)
        {
            if (pageIndex < 0)
            {
                throw new ArgumentException("Invalid less than parameter", "pageIndex");
            }
            if (pageSize < 1)
            {
                throw new ArgumentException("Invalid less than parameter", "pageSize");
            }

            long upperBound = (long)pageIndex * pageSize + pageSize - 1;
            if (upperBound > Int32.MaxValue)
            {
                throw new ArgumentException("Page size too big");
            }
        }

        internal static void CheckPersonalizationScope(PersonalizationScope scope)
        {
            if (scope < PersonalizationScope.User || scope > PersonalizationScope.Shared)
            {
                throw new ArgumentOutOfRangeException("scope");
            }
        }

        internal static void CheckUsernamesInSharedScope(string[] usernames)
        {
            if (usernames != null)
            {
                throw new ArgumentException("No usernames should be set in shared scope");
            }
        }

    }
}
