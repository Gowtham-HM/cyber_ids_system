import numpy as np

class RQAAnalyzer:
    def __init__(self, window_size=50, epsilon=50):
        """
        Initializes the RQA Analyzer.
        :param window_size: Number of recent data points to keep (sliding window).
        :param epsilon: Threshold distance to consider two points as 'recurring'.
        """
        self.window_size = window_size
        self.epsilon = epsilon
        self.data_window = []

    def add_data_point(self, value):
        """Adds a data point (e.g., packet size) to the sliding window."""
        self.data_window.append(value)
        if len(self.data_window) > self.window_size:
            self.data_window.pop(0)

    def calculate_rqa(self):
        """
        Calculates Recurrence Rate (RR) and Determinism (DET).
        :return: Dictionary with 'rr' and 'det' percentages.
        """
        if len(self.data_window) < 2:
            return {'rr': 0.0, 'det': 0.0}

        data = np.array(self.data_window)
        n = len(data)
        
        # Create Distance Matrix: |x_i - x_j|
        # Uses broadcasting to create an n x n matrix of absolute differences
        d_matrix = np.abs(data[:, None] - data)
        
        # Create Recurrence Matrix: 1 if distance < epsilon, else 0
        r_matrix = (d_matrix < self.epsilon).astype(int)
        
        # --- Calculate Recurrence Rate (RR) ---
        # RR = (Total Recurrent Points) / (Total Possible Points)
        # We subtract n from the sum because the main diagonal (i=j) is always 1 (self-similarity)
        # and usually excluded in RQA, or included. Here we exclude it for sensitivity.
        num_recurrence = np.sum(r_matrix) - n 
        total_points = n * n - n
        
        rr = num_recurrence / total_points if total_points > 0 else 0
        
        # --- Calculate Determinism (DET) ---
        # DET = (Points in Diagonal Lines) / (Total Recurrent Points)
        # Diagonal lines indicate predictable sequences (determinism).
        # We look for diagonal lines of length >= 2.
        
        diagonal_points = 0
        # Iterate through upper diagonals (offset k=1 to n-1)
        # We multiply by 2 at the end because the matrix is symmetric
        for k in range(1, n):
            diag = np.diagonal(r_matrix, offset=k)
            
            # Find sequences of 1s with length >= 2
            current_line_length = 0
            for val in diag:
                if val == 1:
                    current_line_length += 1
                else:
                    if current_line_length >= 2:
                        diagonal_points += current_line_length
                    current_line_length = 0
            
            # Check end of diagonal
            if current_line_length >= 2:
                diagonal_points += current_line_length
                
        # Multiply by 2 for the lower triangle (symmetric)
        diagonal_points *= 2
        
        det = diagonal_points / num_recurrence if num_recurrence > 0 else 0
        
        return {
            'rr': round(rr * 100, 1),
            'det': round(det * 100, 1)
        }
