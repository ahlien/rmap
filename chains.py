# import concurrent.futures
# import argparse
# from collections import deque, defaultdict

# def parse_input(line):
#     if ']' in line:
#         parts = line.split(']  [')
#         if len(parts) == 2:
#             # Extract domain and edges
#             domain_part = parts[0]
#             domain = domain_part.split('[')[0].rstrip(':')
#             edges_str = domain_part.split('[')[1]
#             edges = edges_str.split(',')
#             edges = [edge for edge in edges if edge]
            
#             # Extract node data
#             node_data_str = parts[1].rstrip(']')
#             node_data_list = node_data_str.split(') ')
#             node_statuses = {}
#             node_data_list = [node.strip() for node in node_data_list if node.strip()]
#             for node_str in node_data_list:
#                 if node_str == ' ':
#                     continue
#                 node_id, rest = node_str.split('(', 1)
#                 node_id = int(node_id)
#                 rest = rest.rstrip(') ')
#                 parts = rest.split(', ')
#                 status = int(parts[-1])  # Only store the status
#                 node_statuses[node_id] = status
            
#             return domain, edges, node_statuses
#     return None, [], {}

# def build_graph(edges):
#     graph = {}
#     for edge in edges:
#         start, end = map(int, edge.split('>'))
#         if start not in graph:
#             graph[start] = []
#         graph[start].append(end)
#     return graph

# def find_all_paths(graph, start_node, max_paths=1000000):
#     def dfs(node, path):
#         if len(paths) >= max_paths:
#             return
#         path.append(node)
#         if node not in graph:  # No further nodes to visit
#             paths.append(list(path))
#         else:
#             next_nodes = [neighbor for neighbor in graph[node] if neighbor not in path]
#             if not next_nodes:  # No unvisited neighbors left
#                 paths.append(list(path))
#             for neighbor in next_nodes:
#                 dfs(neighbor, path)
#         path.pop()

#     paths = []
#     dfs(start_node, [])
#     return paths

# def compute_node_levels(graph, start_node):
#     levels = {start_node: 0}
#     level_count = defaultdict(int)
#     queue = deque([start_node])
    
#     while queue:
#         current = queue.popleft()
#         current_level = levels[current]
#         level_count[current_level] += 1
        
#         for neighbor in graph.get(current, []):
#             if neighbor not in levels:  # Only visit unvisited nodes
#                 levels[neighbor] = current_level + 1
#                 queue.append(neighbor)
    
#     return levels, level_count

# def process_line(line):
#     try:
#         if line is None:
#             return None
#         line = line.strip()
#         domain, edges, node_statuses = parse_input(line)
#         if edges:
#             graph = build_graph(edges)
            
#             # Find all paths from node 1
#             paths = find_all_paths(graph, 1)
            
#             # Compute node levels
#             node_levels, level_count = compute_node_levels(graph, 1)
#             total_nodes = len(node_levels)  # Total number of nodes
            
#             # Calculate failure rate
#             failure_rate_sum = 0
#             processed_failure_nodes = set()

#             if len(paths) == 1000000:
#                 print(domain, " too large")
#                 return None
            
#             for path in paths:
#                 last_node = path[-1]
#                 last_node_status = node_statuses.get(last_node, -1)  # Default to -1 if not found
#                 if last_node_status not in [11, 12]:  # Failure condition
#                     if last_node not in processed_failure_nodes:
#                         level = node_levels[last_node]
#                         level_node_count = level_count[level]
#                         failure_rate_sum += 1 / level_node_count
#                         processed_failure_nodes.add(last_node)

#             # Use the total failure rate sum as the final failure rate
#             failure_rate = failure_rate_sum
            
#             # Output results
#             level_info = ', '.join(f"Level {level}: {count}" for level, count in sorted(level_count.items()))
#             return f"{domain} {total_nodes} {len(paths)} {failure_rate:.4f} - {level_info}"
#         return None
#     except Exception as e:
#         print(f"Error processing line: {line}\nException: {e}")
#         return None

# def read_lines(file_path):
#     with open(file_path, 'r') as file:
#         for line in file:
#             yield line

# # Main execution
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Process a log file.")
#     parser.add_argument("file_path", help="The path to the log file to process.")
    
#     args = parser.parse_args()
#     file_path = args.file_path

#     try:
#         with concurrent.futures.ThreadPoolExecutor(max_workers=400) as executor:
#             # Create a generator to read lines from the file
#             line_generator = read_lines(file_path)
            
#             # Submit tasks for processing lines and print results
#             while True:
#                 lines = [next(line_generator, None) for _ in range(10)]
#                 if not any(lines):
#                     break

#                 futures = {executor.submit(process_line, line): line for line in lines}
                
#                 for future in concurrent.futures.as_completed(futures):
#                     result = future.result()
#                     if result:
#                         print(result)
#     except FileNotFoundError:
#         print(f"File {file_path} not found.")



import concurrent.futures
import argparse
from collections import deque, defaultdict

def parse_input(line):
    if ']' in line:
        parts = line.split(']  [')
        if len(parts) == 2:
            # Extract domain and edges
            domain_part = parts[0]
            domain = domain_part.split('[')[0].rstrip(':')
            edges_str = domain_part.split('[')[1]
            edges = edges_str.split(',')
            edges = [edge for edge in edges if edge]
            
            # Extract node data
            node_data_str = parts[1].rstrip(']')
            node_data_list = node_data_str.split(') ')
            node_statuses = {}
            node_data_list = [node.strip() for node in node_data_list if node.strip()]
            for node_str in node_data_list:
                if node_str == ' ':
                    continue
                node_id, rest = node_str.split('(', 1)
                node_id = int(node_id)
                rest = rest.rstrip(') ')
                parts = rest.split(', ')
                status = int(parts[-1])  # Only store the status
                node_statuses[node_id] = status
            
            return domain, edges, node_statuses
    return None, [], {}

def build_graph(edges):
    graph = {}
    for edge in edges:
        start, end = map(int, edge.split('>'))
        if start not in graph:
            graph[start] = []
        graph[start].append(end)
    return graph

def find_all_paths(graph, start_node, max_paths=1000000):
    def dfs(node, path):
        if len(paths) >= max_paths:
            return
        path.append(node)
        if node not in graph:  # No further nodes to visit
            paths.append(list(path))
        else:
            next_nodes = [neighbor for neighbor in graph[node] if neighbor not in path]
            if not next_nodes:  # No unvisited neighbors left
                paths.append(list(path))
            for neighbor in next_nodes:
                dfs(neighbor, path)
        path.pop()

    paths = []
    dfs(start_node, [])
    return paths

def compute_node_levels(graph, start_node):
    levels = {start_node: 0}
    level_count = defaultdict(int)
    queue = deque([start_node])
    
    while queue:
        current = queue.popleft()
        current_level = levels[current]
        level_count[current_level] += 1
        
        for neighbor in graph.get(current, []):
            if neighbor not in levels:  # Only visit unvisited nodes
                levels[neighbor] = current_level + 1
                queue.append(neighbor)
    
    return levels, level_count

def calculate_failure_rate(paths, node_statuses, node_levels, level_count):
    processed_failure_nodes = set()
    failure_rate = 0.0
    cumulative_success_rate = 1.0  # Start with the full probability (100%)

    # Group paths by their length
    paths_by_length = defaultdict(list)
    for path in paths:
        paths_by_length[len(path)].append(path)

    # Process paths starting from the shortest ones
    for length in sorted(paths_by_length.keys()):
        current_failure_rate_sum = 0.0

        for path in paths_by_length[length]:
            last_node = path[-1]
            last_node_status = node_statuses.get(last_node, -1)  # Default to -1 if not found

            # Check if the last node in the path indicates a failure
            if last_node_status not in [11, 12]:  # Failure condition
                if last_node not in processed_failure_nodes:
                    level = node_levels[last_node]
                    level_node_count = level_count[level]
                    current_failure_rate_sum += 1 / level_node_count
                    processed_failure_nodes.add(last_node)

        # Update the cumulative failure rate considering the success rate so far
        failure_rate += cumulative_success_rate * current_failure_rate_sum
        cumulative_success_rate *= (1 - current_failure_rate_sum)

    return failure_rate

def process_line(line):
    try:
        if line is None:
            return None
        line = line.strip()
        domain, edges, node_statuses = parse_input(line)
        if edges:
            graph = build_graph(edges)
            
            # Find all paths from node 1
            paths = find_all_paths(graph, 1)
            
            # Compute node levels
            node_levels, level_count = compute_node_levels(graph, 1)
            total_nodes = len(node_levels)  # Total number of nodes
            
            if len(paths) == 1000000:
                print(domain, " too large")
                return None
            
            # Calculate failure rate
            failure_rate = calculate_failure_rate(paths, node_statuses, node_levels, level_count)
            
            # Output results
            level_info = ', '.join(f"Level {level}: {count}" for level, count in sorted(level_count.items()))
            return f"{domain} {total_nodes} {len(paths)} {failure_rate:.4f} - {level_info}"
        return None
    except Exception as e:
        print(f"Error processing line: {line}\nException: {e}")
        return None

def read_lines(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            yield line

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a log file.")
    parser.add_argument("file_path", help="The path to the log file to process.")
    
    args = parser.parse_args()
    file_path = args.file_path

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            # Create a generator to read lines from the file
            line_generator = read_lines(file_path)
            
            # Submit tasks for processing lines and print results
            while True:
                lines = [next(line_generator, None) for _ in range(10)]
                if not any(lines):
                    break

                futures = {executor.submit(process_line, line): line for line in lines}
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        print(result)
    except FileNotFoundError:
        print(f"File {file_path} not found.")